#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <linux/types.h>

#include <net/if.h>

#include <sys/socket.h>
#include <linux/if_link.h>
#include <bpf.h>
#include <xsk.h>

#include "af_xdp.h"

/* Global variables */
// The XDP flags to load the AF_XDP/XSK sockets with.
__u32 xdp_flags = XDP_FLAGS_DRV_MODE;
__u32 bind_flags = XDP_USE_NEED_WAKEUP;
__u8 shared_umem = 0;
__u16 batch_size = 1;
int static_queue_id = 0;
int queue_id = 0;

// Pointers to the umem and XSK sockets for each thread.
struct xsk_umem_info *umem[MAX_CPUS];
struct xsk_socket_info *xsk_socket[MAX_CPUS];

/**
 * Assigns an address to a free UMEM frame.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * @param frame The address to assign to the UMEM frame.
 * 
 * @return Void
**/
static void xsk_free_umem_frame(struct xsk_socket_info *xsk, __u64 frame)
{
    if (xsk->umem_frame_free < NUM_FRAMES)
    {
        fprintf(stderr, "WARNING - UMEM free frame count is lower than the number of frames we specified.\n");

        return;
    }

    // Assign the frame address to the free UMEM frame.
    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

/**
 * Completes the TX call via a syscall and also checks if we need to free the TX buffer.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * 
 * @return Void
**/
static void complete_tx(struct xsk_socket_info *xsk)
{
    // Initiate starting variables (completed amount and completion ring index).
    unsigned int completed;
    uint32_t idx_cq;

    // If outstanding is below 1, it means we have no packets to TX.
    if (!xsk->outstanding_tx)
    {
        return;
    }

    // If we need to wakeup, execute syscall to wake up socket.
    if (!(bind_flags & XDP_USE_NEED_WAKEUP) || xsk_ring_prod__needs_wakeup(&xsk->tx))
    {
        sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

    // If the TX buffer is filled, we need to free all frames and decrease the amount of outstanding TX packets.
    completed = xsk_ring_cons__peek(&xsk->umem->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

    if (completed > 0) 
    {
        // Release "completed" frames.
        xsk_ring_cons__release(&xsk->umem->cq, completed);

        xsk->outstanding_tx -= completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
    }
}

/**
 * Configures the UMEM area for our AF_XDP/XSK sockets to use for rings.
 * 
 * @param buffer The blank buffer we allocated in setup_socket().
 * @param size The buffer size.
 * 
 * @return Returns a pointer to the UMEM area instead of the XSK UMEM information structure (struct xsk_umem_info).
**/
static struct xsk_umem_info *configure_xsk_umem(void *buffer, __u64 size)
{
    // Create umem pointer and return variable.
    struct xsk_umem_info *umem;
    int ret;

    // Allocate memory space to the umem pointer and check.
    umem = calloc(1, sizeof(*umem));

    if (!umem)
    {
        return NULL;
    }

    // Attempt to create the umem area and check.
    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);

    if (ret) 
    {
        errno = -ret;
        return NULL;
    }

    // Assign the buffer we created in setup_socket() to umem buffer.
    umem->buffer = buffer;

    // Return umem pointer.
    return umem;
}

/**
 * Configures an AF_XDP/XSK socket.
 * 
 * @param umem A pointer to the umem we created in setup_socket().
 * @param queue_id The TX queue ID to use.
 * @param dev The name of the interface we're binding to.
 * 
 * @return Returns a pointer to the AF_XDP/XSK socket inside of a the XSK socket info structure (struct xsk_socket_info).
**/
static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem, int queue_id, const char *dev)
{
    // Initialize starting variables.
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    __u32 idx;
    int i;
    int ret;

    // Allocate memory space to our XSK socket.
    xsk_info = calloc(1, sizeof(*xsk_info));

    // If it fails, return.
    if (!xsk_info)
    {
        fprintf(stderr, "Failed to allocate memory space to AF_XDP/XSK socket.\n");

        return NULL;
    }

    // Assign AF_XDP/XSK's socket umem area to the umem we allocated before.
    xsk_info->umem = umem;
    
    // Set the TX size (we don't need anything RX-related).
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;

    // Make sure we don't load an XDP program via LibBPF.
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

    // Assign our XDP flags.
    xsk_cfg.xdp_flags = xdp_flags;

    // Assign bind flags.
    xsk_cfg.bind_flags = bind_flags;

    // Attempt to create the AF_XDP/XSK socket itself at queue ID (we don't allocate a RX queue for obvious reasons).
    ret = xsk_socket__create(&xsk_info->xsk, dev, queue_id, umem->umem, NULL, &xsk_info->tx, &xsk_cfg);

    if (ret)
    {
        fprintf(stderr, "Failed to create AF_XDP/XSK socket at creation.\n");

        goto error_exit;
    }

    // Assign each umem frame to an address we'll use later.
    for (i = 0; i < NUM_FRAMES; i++)
    {
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
    }

    // Assign how many number of frames we can hold.
    xsk_info->umem_frame_free = NUM_FRAMES;

    // Return the AF_XDP/XSK socket information itself as a pointer.
    return xsk_info;

    // Handle error and return NULL.
    error_exit:
    errno = -ret;

    return NULL;
}

/**
 * Sends a packet buffer out the AF_XDP socket's TX path.
 * 
 * @param thread_id The thread ID to use to lookup the AF_XDP socket.
 * @param pckt The packet buffer starting at the Ethernet header.
 * @param length The packet buffer's length.
 * @param verbose Whether verbose is enabled or not.
 * 
 * @return Returns 0 on success and -1 on failure.
**/
int send_packet(int thread_id, void *pckt, __u16 length, __u8 verbose)
{
    // This represents the TX index.
    __u32 tx_idx = 0;

    // Retrieve the TX index from the TX ring to fill.
    int ret = xsk_ring_prod__reserve(&xsk_socket[thread_id]->tx, 1, &tx_idx);

    // If we don't have 1, there are no TX slots available.
    if (ret != 1)
    {
        #ifdef DEBUG
        fprintf(stderr, "[AF_XDP] No more TX slots available.\n");
        #endif

        return -1;
    }

    // We must retrieve the available address in the umem to copy our packet data to.
    __u64 addrat = xsk_socket[thread_id]->umem_frame_addr[xsk_socket[thread_id]->outstanding_tx];

    // We must copy our packet data to the umem area at the specific index (idx * frame size). We did this earlier.
    memcpy(xsk_umem__get_data(xsk_socket[thread_id]->umem->buffer, addrat), pckt, length);

    // Point the TX ring's frame address to what we have in the umem.
    xsk_ring_prod__tx_desc(&xsk_socket[thread_id]->tx, tx_idx)->addr = addrat;

    // Tell the TX ring the packet length.
    xsk_ring_prod__tx_desc(&xsk_socket[thread_id]->tx, tx_idx)->len = length;

    // Submit the TX packet to the producer ring.
    xsk_ring_prod__submit(&xsk_socket[thread_id]->tx, 1);

    // Increase outstanding.
    xsk_socket[thread_id]->outstanding_tx++;

    // Complete the TX.
    complete_tx(xsk_socket[thread_id]);

    // Return successful.
    return 0;
}

/**
 * Sets global variables from command line.
 * 
 * @param cmd_af_xdp A pointer to the AF_XDP-specific command line variable.
 * @param verbose Whether we should print verbose.
 * 
 * @return Void
**/
void setup_af_xdp_variables(struct cmd_line_af_xdp *cmd_af_xdp, int verbose)
{
    // Check for zero-copy or copy modes.
    if (cmd_af_xdp->zero_copy)
    {
        if (verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets in zero-copy mode.\n");
        }

        bind_flags |= XDP_ZEROCOPY;
    }
    else if (cmd_af_xdp->copy)
    {
        if (verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets in copy mode.\n");
        }

        bind_flags |= XDP_COPY;
    }

    // Check for no wakeup mode.
    if (cmd_af_xdp->no_wake_up)
    {
        if (verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets in no wake-up mode.\n");
        }

        bind_flags &= ~XDP_USE_NEED_WAKEUP; 
    }

    // Check for a static queue ID.
    if (cmd_af_xdp->queue_set)
    {
        static_queue_id = 1;
        queue_id = cmd_af_xdp->queue;

        if (verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets with one queue ID => %d.\n", queue_id);
        }
    }

    // Check for shared UMEM.
    if (cmd_af_xdp->shared_umem)
    {
        if (verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets with shared UMEM mode.\n");
        }

        shared_umem = 1;
        //bind_flags |= XDP_SHARED_UMEM;
    }

    // Check for SKB mode.
    if (cmd_af_xdp->skb_mode)
    {
        if (verbose)
        {
            fprintf(stdout, "Running AF_XDP sockets in SKB mode.\n");
        }

        xdp_flags = XDP_FLAGS_SKB_MODE;
    }

    // Assign batch size.
    batch_size = cmd_af_xdp->batch_size;

    if (verbose)
    {
        fprintf(stdout, "Running AF_XDP sockets with batch size => %d.\n", batch_size);
    }
}

/**
 * Sets up UMEM at specific index.
 * 
 * @param index Sets up UMEM at a specific index.
 * 
 * @return 0 on success and -1 on failure.
**/
int setup_umem(int index)
{
    // This indicates the buffer for frames and frame size for the UMEM area.
    void *frame_buffer;
    __u64 frame_buffer_size = NUM_FRAMES * FRAME_SIZE;

    // Allocate blank memory space for the UMEM (aligned in chunks). Check as well.
    if (posix_memalign(&frame_buffer, getpagesize(), frame_buffer_size)) 
    {
        fprintf(stderr, "Could not allocate buffer memory for UMEM index #%d => %s (%d).\n", index, strerror(errno), errno);

        return -1;
    }

    umem[index] = configure_xsk_umem(frame_buffer, frame_buffer_size);

    // Check the UMEM.
    if (umem[index] == NULL) 
    {
        fprintf(stderr, "Could not create UMEM at index %d ::  %s (%d).\n", index, strerror(errno), errno);

        return -1;
    }

    return 0;
}

/**
 * Sets up XSK (AF_XDP) socket.
 * 
 * @param dev The interface the XDP program exists on (string).
 * @param thread_id The thread ID/number.
 * 
 * @return Returns the AF_XDP's socket FD or -1 on failure.
**/
int setup_socket(const char *dev, __u16 thread_id)
{
    // Initialize starting variables.
    int ret;
    int xsks_map_fd;

    // Verbose message.
    fprintf(stdout, "Attempting to setup AF_XDP socket. Dev => %s. Thread ID => %d.\n", dev, thread_id);

    // Configure the UMEM and provide the memory we allocated.
    if (!shared_umem || thread_id > 0)
    {
        if (setup_umem(thread_id) != 0)
        {
            return -1;
        }

        fprintf(stdout, "Created UMEM at index %d.\n", thread_id);
    }

    // Configure and create the AF_XDP/XSK socket.
    int id = (shared_umem) ? 0 : thread_id;
    struct xsk_umem_info *xsk_to_use = umem[id];

    if (xsk_to_use == NULL)
    {
        fprintf(stderr, "Somehow UMEM to use is NULL at index %d.\n", id);

        return -1;
    }

    xsk_socket[thread_id] = xsk_configure_socket(xsk_to_use, (static_queue_id) ? queue_id : thread_id, (const char *)dev);

    // Check to make sure it's valid.
    if (xsk_socket[thread_id] == NULL) 
    {
        fprintf(stderr, "Could not setup AF_XDP socket (#%d) :: %s (%d).\n", thread_id, strerror(errno), errno);

        return -1;
    }

    // Retrieve the AF_XDP/XSK's socket FD and do a verbose print.
    int fd = xsk_socket__fd(xsk_socket[thread_id]->xsk);

    fprintf(stdout, "Created AF_XDP socket #%d (FD => %d).\n", thread_id, fd);

    // Return the socket's file descriptor.
    return fd;
}

/**
 * Cleans up a specific AF_XDP/XSK socket.
 * 
 * @param id The ID of the specific AF_XDP socket.
 * 
 * @return Void
**/
void cleanup_socket(__u16 id)
{
    // If the AF_XDP/XSK socket isn't NULL, delete it.
    if (xsk_socket[id] != NULL)
    {
        xsk_socket__delete(xsk_socket[id]->xsk);
    }

    // If the UMEM isn't NULL, delete it.
    if (umem[id] != NULL)
    {
        xsk_umem__delete(umem[id]->umem);
    }
}