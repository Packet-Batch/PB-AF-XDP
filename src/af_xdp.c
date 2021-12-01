#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <net/if.h>

#include <linux/types.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf.h>
#include <xsk.h>

#include <arpa/inet.h>

#include "af_xdp.h"

__u32 flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;

struct xsk_umem_info *umem[MAX_CPUS];
struct xsk_socket_info *xsk_socket[MAX_CPUS];

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, __u64 frame)
{
    assert(xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk->outstanding_tx)
    {
        return;
    }

    if (xsk_ring_prod__needs_wakeup(&xsk->tx))
    {
        int fd = xsk_socket__fd(xsk->xsk);
        printf("sendto() executed with FD %d.\n", fd);
        sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

    /* Collect/free completed TX buffers */
    completed = xsk_ring_cons__peek(&xsk->umem->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

    if (completed > 0)
    {
        printf("completed > 0.\n");

        for (int i = 0; i < completed; i++)
        {
            xsk_free_umem_frame(xsk, *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++));
        }

        xsk_ring_cons__release(&xsk->umem->cq, completed);
        xsk->outstanding_tx -= completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
        printf("New outstanding TX => %u.\n", xsk->outstanding_tx);
    }
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, __u64 size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));

    if (!umem)
    {
        return NULL;
    }

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);

    if (ret) 
    {
        errno = -ret;
        return NULL;
    }

    umem->buffer = buffer;

    return umem;
}

static __u64 xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    __u64 frame;

    if (xsk->umem_frame_free == 0)
    {
        return INVALID_UMEM_FRAME;
    }

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;

    return frame;
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem, int queue_id, int ifidx, const char *dev)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    __u32 idx;
    int i;
    int ret;

    xsk_info = calloc(1, sizeof(*xsk_info));

    if (!xsk_info)
    {
        fprintf(stderr, "xsk_info = NULL\n");

        return NULL;
    }

    xsk_info->umem = umem;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    xsk_cfg.xdp_flags = flags;
    xsk_cfg.bind_flags = XDP_USE_NEED_WAKEUP;

    ret = xsk_socket__create(&xsk_info->xsk, dev, queue_id, umem->umem, NULL, &xsk_info->tx, &xsk_cfg);

    if (ret)
    {
        //fprintf(stderr, "xdp_socket__create :: Error.\n");

        goto error_exit;
    }

    // Initialize umem frame allocation.
    for (i = 0; i < NUM_FRAMES; i++)
    {
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
    }

    xsk_info->umem_frame_free = NUM_FRAMES;

    return xsk_info;

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
int send_packet(int thread_id, void *pckt, __u32 length, __u8 verbose)
{
    __u64 addr = (__u64)pckt;

    struct ethhdr *eth = (struct ethhdr *)addr;

    struct iphdr *iph = (struct iphdr *)(eth + 1);

    printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx => %hhx:%hhx:%hhx:%hhx:%hhx:%hhx.\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5], eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("%u => %u.\n", iph->saddr, iph->daddr);

    __u32 tx_idx = 0;

    int ret = xsk_ring_prod__reserve(&xsk_socket[thread_id]->tx, 1, &tx_idx);

    if (ret != 1)
    {
        #ifdef DEBUG
        fprintf(stderr, "[AF_XDP] No more TX slots available.\n");
        #endif

        return -1;
    }

    xsk_ring_prod__tx_desc(&xsk_socket[thread_id]->tx, tx_idx)->addr = (__u64)pckt;
    xsk_ring_prod__tx_desc(&xsk_socket[thread_id]->tx, tx_idx)->len = length;
    xsk_ring_prod__submit(&xsk_socket[thread_id]->tx, 1);
    xsk_socket[thread_id]->outstanding_tx++;

    if (verbose)
    {
        printf("AF_XDP Info :: Address => %llu. Length => %u. Outstanding TX => %u. TX Index => %u.\n", (__u64)pckt, length, xsk_socket[thread_id]->outstanding_tx, tx_idx);
    }

    complete_tx(xsk_socket[thread_id]);

    return 0;
}

/**
 * Sets up XSK (AF_XDP) socket.
 * 
 * @param dev The interface the XDP program exists on (string).
 * @param xdp_flags The XDP flags to set on the socket.
 * @param thread_id The thread ID/number.
 * 
 * @return Returns the AF_XDP's socket FD or -1 on failure.
**/
int setup_socket(const char *dev, __u32 xdp_flags, __u16 thread_id)
{
    flags = xdp_flags;
    int ret;
    int xsks_map_fd;
    void *packet_buffer;
    __u64 packet_buffer_size;

    int ifidx = if_nametoindex(dev);

    if (ifidx < 0)
    {
        fprintf(stderr, "Error retrieving interface index (%s) :: %s (%d).\n", dev, strerror(errno), errno);

        return -1;
    }

    fprintf(stdout, "Attempting to setup AF_XDP socket. Dev => %s. Index => %d. Thread ID => %d.\n", dev, ifidx, thread_id);

    // Allocate memory for NUM_FRAMES of the default XDP frame size.
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;

    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) 
    {
        fprintf(stderr, "Could not allocate buffer memory for AF_XDP socket (#%d) => %s (%d).\n", thread_id, strerror(errno), errno);

        return -1;
    }

    // Initialize shared packet_buffer for umem usage.
    umem[thread_id] = configure_xsk_umem(packet_buffer, packet_buffer_size);

    if (umem[thread_id] == NULL) 
    {
        fprintf(stderr, "Could not create umem ::  %s (%d).\n", strerror(errno), errno);

        return -1;
    }

    // Open and configure the AF_XDP (xsk) socket.
    xsk_socket[thread_id] = xsk_configure_socket(umem[thread_id], thread_id, ifidx, (const char *)dev);

    if (xsk_socket[thread_id] == NULL) 
    {
        fprintf(stderr, "Could not setup AF_XDP socket (#%d) :: %s (%d).\n", thread_id, strerror(errno), errno);

        return -1;
    }

    int fd = xsk_socket__fd(xsk_socket[thread_id]->xsk);

    fprintf(stdout, "Created AF_XDP socket #%d (FD => %d).\n", thread_id, fd);

    return fd;
}

/**
 * Cleans up a specific AF_XDP socket.
 * 
 * @param id The ID of the specific AF_XDP socket.
 * 
 * @return Void
**/
void cleanup_socket(__u16 id)
{
    if (xsk_socket[id] != NULL)
    {
        xsk_socket__delete(xsk_socket[id]->xsk);
    }

    if (umem[id] != NULL)
    {
        xsk_umem__delete(umem[id]->umem);
    }
}