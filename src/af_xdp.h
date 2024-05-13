#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>

#include <net/if.h>

#include <sys/socket.h>
#include <linux/if_link.h>
#include <bpf.h>

#include <xsk.h>

#include <simple_types.h>

#include "cmd_line.h"

#define MAX_CPUS 256
#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define INVALID_UMEM_FRAME UINT64_MAX
//#define DEBUG

typedef struct xsk_umem_info 
{
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
} xsk_umem_info_t;

typedef struct xsk_socket 
{
    struct xsk_ring_cons *rx;
    struct xsk_ring_prod *tx;
    u64 outstanding_tx;
    struct xsk_ctx *ctx;
    struct xsk_socket_config config;
    int fd;
} xsk_socket_t;

typedef struct xsk_socket_info
{
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    u64 umem_frame_addr[NUM_FRAMES];
    u32 umem_frame_free;

    u32 outstanding_tx;
} xsk_socket_info_t;

int send_packet(struct xsk_socket_info *xsk, int thread_id, void *pckt, u16 length, u8 verbose);
u64 get_umem_addr(struct xsk_socket_info *xsk, int idx);
void *get_umem_loc(struct xsk_socket_info *xsk, u64 addr);
void setup_af_xdp_variables(struct cmd_line_af_xdp *cmd_af_xdp, int verbose);
struct xsk_umem_info *setup_umem(int index);
struct xsk_socket_info *setup_socket(const char *dev, u16 thread_id, int verbose);
void cleanup_socket(struct xsk_socket_info *xsk);
int get_socket_fd(struct xsk_socket_info *xsk);