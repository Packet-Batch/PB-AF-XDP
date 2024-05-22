#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <linux/if_link.h>

#include <utils.h>
#include <cmd_line.h>
#include <config.h>
#include <simple_types.h>

#include "cmd_line.h"
#include "af_xdp.h"
#include "main.h"

//#define VERY_RANDOM

#define MAX_PCKT_LEN 0xFFFF
#define MAX_THREADS 4096
#define MAX_NAME_LEN 64

typedef struct thread_info
{
    const char device[MAX_NAME_LEN];
    struct sequence seq;
    u16 seq_cnt;
    struct cmd_line cmd;
    int id;
    struct xsk_socket_info *xsk_info;
} thread_info_t;

void seq_send(const char *interface, struct sequence seq, u16 seqc, struct cmd_line cmd);
void shutdown_prog(struct config *cfg);