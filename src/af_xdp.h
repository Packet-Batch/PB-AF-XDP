#pragma once

#include <linux/types.h>
#include <xsk.h>

#include "cmd_line.h"

#define MAX_CPUS 256
#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info 
{
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket 
{
    struct xsk_ring_cons *rx;
    struct xsk_ring_prod *tx;
    __u64 outstanding_tx;
    struct xsk_ctx *ctx;
    struct xsk_socket_config config;
    int fd;
};

struct xsk_socket_info
{
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    __u64 umem_frame_addr[NUM_FRAMES];
    __u32 umem_frame_free;

    __u32 outstanding_tx;
};


int send_packet(int thread_id, void *pckt, __u16 length, __u8 verbose);
void setup_af_xdp_variables(struct cmd_line_af_xdp *cmd_af_xdp, int verbose);
int setup_umem(int index);
int setup_socket(const char *dev, __u16 thread_id);
void cleanup_socket(__u16 id);