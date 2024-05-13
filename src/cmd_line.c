#include "cmd_line.h"

static const struct option long_opts[] =
{
    {"queue", required_argument, NULL, 1},
    {"nowakeup", no_argument, NULL, 2},
    {"sharedumem", no_argument, NULL, 3},
    {"batchsize", required_argument, NULL, 4},
    {"skb", no_argument, NULL, 5},
    {"zerocopy", no_argument, NULL, 6},
    {"copy", no_argument, NULL, 7},
    {NULL, 0, NULL, 0}
};

/**
 * Parses AF_XDP-specific command line.
 * 
 * @param cmd_af_xdp A pointer to the cmd_line_af_xdp structure to put values in.
 * @param argc The argument count.
 * @param argv A pointer reference to the argument value char.
 * 
 * @return Void
**/
void parse_cmd_line_af_xdp(cmd_line_af_xdp_t *cmd_af_xdp, int argc, char **argv)
{
    int c = -1;

    while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1)
    {
        switch (c)
        {
            case 1:
                cmd_af_xdp->queue_set = 1;
                cmd_af_xdp->queue = atoi(optarg);

                break;

            case 2:
                cmd_af_xdp->no_wake_up = 1;

                break;

            case 3:
                cmd_af_xdp->shared_umem = 1;

                break;

            case 4:
                cmd_af_xdp->batch_size = atoi(optarg);

                break;

            case 5:
                cmd_af_xdp->skb_mode = 1;

                break;

            case 6:
                cmd_af_xdp->zero_copy = 1;

                break;

            case 7:
                cmd_af_xdp->copy = 1;

                break;
        }
    }
}