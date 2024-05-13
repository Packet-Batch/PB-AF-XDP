#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

typedef struct cmd_line_af_xdp
{
    unsigned int queue_set : 1;
    int queue;

    unsigned int no_wake_up : 1;
    unsigned int shared_umem;
    unsigned short batch_size;
    unsigned int skb_mode : 1;
    unsigned int zero_copy : 1;
    unsigned int copy : 1;
} cmd_line_af_xdp_t;

void parse_cmd_line_af_xdp(struct cmd_line_af_xdp *cmd_af_xdp, int argc, char **argv);