#include "af_xdp.h"

/* Global variables */
// The XDP flags to load the AF_XDP/XSK sockets with.
u32 xdp_flags = XDP_FLAGS_DRV_MODE;
u32 bind_flags = XDP_USE_NEED_WAKEUP;
int is_shared_umem = 0;
u16 batch_size = 1;
int static_queue_id = 0;
int queue_id = 0;

// For shared UMEM.
static unsigned int global_frame_idx = 0;

// Pointers to the umem and XSK sockets for each thread.
xsk_umem_info_t *shared_umem = NULL;

/**
 * Completes the TX call via a syscall and also checks if we need to free the TX buffer.
 * 
 * @param xsk A pointer to the xsk_socket_info structure.
 * 
 * @return Void
**/
static void complete_tx(xsk_socket_info_t *xsk)
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

    // Try to free n (batch_size) frames on the completetion ring.
    completed = xsk_ring_cons__peek(&xsk->umem->cq, batch_size, &idx_cq);

    if (completed > 0) 
    {
        // Release "completed" frames.
        xsk_ring_cons__release(&xsk->umem->cq, completed);

        xsk->outstanding_tx -= completed;
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
static xsk_umem_info_t *configure_xsk_umem(void *buffer, u64 size)
{
    // Create umem pointer and return variable.
    xsk_umem_info_t *umem;
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
static xsk_socket_info_t *xsk_configure_socket(xsk_umem_info_t *umem, int queue_id, const char *dev)
{
    // Initialize starting variables.
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    u32 idx;
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
 * @param xsk A pointer to the XSK socket info.
 * @param thread_id The thread ID to use to lookup the AF_XDP socket.
 * @param pckt The packet buffer starting at the Ethernet header.
 * @param length The packet buffer's length.
 * @param verbose Whether verbose is enabled or not.
 * 
 * @return Returns 0 on success and -1 on failure.
**/
int send_packet(xsk_socket_info_t *xsk, int thread_id, void *pckt, u16 length, u8 verbose)
{
    // This represents the TX index.
    u32 tx_idx = 0;

    // Retrieve the TX index from the TX ring to fill.
    while (xsk_ring_prod__reserve(&xsk->tx, batch_size, &tx_idx) < batch_size)
    {
#ifdef DEBUG
        fprintf(stdout, "Completing TX (amount => %u)...\n", amt);
#endif       
        complete_tx(xsk);
    }
    

#ifdef DEBUG
    fprintf(stdout, "Sending packet in a batch size of %d...\n", batch_size);
#endif

    unsigned int idx = 0;

    // Loop through to batch size.
    for (int i = 0; i < batch_size; i++)
    {
        // Retrieve index we want to insert at in UMEM and make sure it isn't equal/above to max number of frames.
        idx = xsk->outstanding_tx + i;

        if (idx > NUM_FRAMES)
        {
            break;
        }

        // We must retrieve the next available address in the UMEM.
        u64 addrat = get_umem_addr(xsk, idx);

        // We must copy our packet data to the UMEM area at the specific index (idx * frame size). We did this earlier.
        memcpy(get_umem_loc(xsk, addrat), pckt, length);

        // Retrieve TX descriptor at index.
        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx + i);

        // Point the TX ring's frame address to what we have in the UMEM.
        tx_desc->addr = addrat;

        // Tell the TX ring the packet length.
        tx_desc->len = length;
    }

    // Submit the TX batch to the producer ring.
    xsk_ring_prod__submit(&xsk->tx, batch_size);

    // Increase outstanding.
    xsk->outstanding_tx += batch_size;

    // Complete TX again.
    complete_tx(xsk);

#ifdef DEBUG
    fprintf(stdout, "Completed batch with %u outstanding packets...\n", xsk_socket[thread_id]->outstanding_tx);
#endif

    // Return successful.
    return 0;
}

/**
 * Retrieves the socket FD of XSK socket.
 * 
 * @param xsk A pointer to the XSK socket info.
 * 
 * @return The socket FD (-1 on failure)
*/
int get_socket_fd(xsk_socket_info_t *xsk)
{
    return xsk_socket__fd(xsk->xsk);
}

/**
 * Retrieves UMEM address at index we can fill with packet data.
 * 
 * @param xsk A pointer to the XSK socket info.
 * @param idx The index we're retrieving (make sure it is below NUM_FRAMES).
 * 
 * @return 64-bit address of location.
**/
u64 get_umem_addr(xsk_socket_info_t *xsk, int idx)
{
    return xsk->umem_frame_addr[idx];
}

/**
 * Retrieves the memory location in the UMEM at address.
 * 
 * @param xsk A pointer to the XSK socket info.
 * @param addr The address received by get_umem_addr.
 * 
 * @return Pointer to address in memory of UMEM.
**/
void *get_umem_loc(xsk_socket_info_t *xsk, u64 addr)
{
    return xsk_umem__get_data(xsk->umem->buffer, addr);
}

/**
 * Sets global variables from command line.
 * 
 * @param cmd_af_xdp A pointer to the AF_XDP-specific command line variable.
 * @param verbose Whether we should print verbose.
 * 
 * @return Void
**/
void setup_af_xdp_variables(cmd_line_af_xdp_t *cmd_af_xdp, int verbose)
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

        is_shared_umem = 1;
        /* Note - Although documentation states to set bind flag XDP_SHARED_UMEM, this results in segfault and official sample with shared UMEMs does not do this. */
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
 * @param thread_id The thread ID/number.
 * 
 * @return 0 on success and -1 on failure.
**/
xsk_umem_info_t *setup_umem(int thread_id)
{
    // This indicates the buffer for frames and frame size for the UMEM area.
    void *frame_buffer;
    u64 frame_buffer_size = NUM_FRAMES * FRAME_SIZE;

    // Allocate blank memory space for the UMEM (aligned in chunks). Check as well.
    if (posix_memalign(&frame_buffer, getpagesize(), frame_buffer_size)) 
    {
        fprintf(stderr, "Could not allocate buffer memory for UMEM index #%d => %s (%d).\n", thread_id, strerror(errno), errno);

        return NULL;
    }

    return configure_xsk_umem(frame_buffer, frame_buffer_size);
}

/**
 * Sets up XSK (AF_XDP) socket.
 * 
 * @param dev The interface the XDP program exists on (string).
 * @param thread_id The thread ID/number.
 * @param verbose Whether verbose mode is enabled.
 * 
 * @return Returns the AF_XDP's socket FD or -1 on failure.
**/
xsk_socket_info_t *setup_socket(const char *dev, u16 thread_id, int verbose)
{
    // Verbose message.
    if (verbose)
    {
        fprintf(stdout, "Attempting to setup AF_XDP socket. Dev => %s. Thread ID => %d.\n", dev, thread_id);
    }

    // Configure and create the AF_XDP/XSK socket.
    xsk_umem_info_t *umem;

    // Check for shared UMEM.
    if (is_shared_umem)
    {
        // Check if we need to allocate shared UMEM.
        if (shared_umem == NULL)
        {
            shared_umem = setup_umem(thread_id);

            if (shared_umem == NULL)
            {
                fprintf(stderr, "Failed to setup shared UMEM.\n");

                return NULL;
            }
        }

        umem = shared_umem;
    }
    else
    {
        // Otherwise, allocate our own UMEM for this thread/socket.
        umem = setup_umem(thread_id);
    }

    // Although this shouldn't happen, just check here in-case.
    if (umem == NULL)
    {
        fprintf(stderr, "UMEM at index 0 is NULL. Aborting...\n");

        return NULL;
    }

    xsk_socket_info_t *xsk = xsk_configure_socket(umem, (static_queue_id) ? queue_id : thread_id, (const char *)dev);

    // Check to make sure it's valid.
    if (xsk == NULL)
    {
        fprintf(stderr, "Could not setup AF_XDP socket at index %d :: %s (%d).\n", thread_id, strerror(errno), errno);

        return xsk;
    }

    // Retrieve the AF_XDP/XSK's socket FD and do a verbose print.
    int fd = xsk_socket__fd(xsk->xsk);

    if (verbose)
    {
        fprintf(stdout, "Created AF_XDP socket at index %d (FD => %d).\n", thread_id, fd);
    }

    // Return XSK socket.
    return xsk;
}

/**
 * Cleans up a specific AF_XDP/XSK socket.
 * 
 * @param xsk A pointer to the XSK socket info.
 * 
 * @return Void
**/
void cleanup_socket(xsk_socket_info_t *xsk)
{
    // If the AF_XDP/XSK socket isn't NULL, delete it.
    if (xsk->xsk != NULL)
    {
        xsk_socket__delete(xsk->xsk);
    }

    // If the UMEM isn't NULL, delete it.
    if (xsk->umem != NULL)
    {
        xsk_umem__delete(xsk->umem->umem);
    }
}