#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <getopt.h>

#include <utils.h>
#include <cmd_line.h>
#include <config.h>

#include "sequence.h"
#include "cmd_line.h"
#include "af_xdp.h"
#include "main.h"

int main(int argc, char *argv[])
{
    // Create command line structure.
    opterr = 0;
    struct cmd_line cmd = {0};

    // Parse command line and store values into cmd.
    parse_cmd_line(argc, argv, &cmd);

    // Help menu.
    if (cmd.help)
    {
        fprintf(stdout, "Usage: pcktseq -c <configfile> [-v -h]\n\n" \
            "-c --cfg => Path to YAML file to parse.\n" \
            "-l --list => Print basic information about sequences.\n"
            "-v --verbose => Provide verbose output.\n" \
            "-h --help => Print out help menu and exit program.\n" \
            "--queue => If set, all AF_XDP/XSK sockets are bound to this specific queue ID.\n" \
            "--nowakeup => If set, all AF_XDP/XSK sockets are bound without the wakeup flag.\n" \
            "--sharedumem => If set, all AF_XDP/XSK sockets use the same UMEM area.\n" \
            "--batchsize => How many packets to send at once (default 1).\n" \
            "--forceskb => If set, all AF_XDP/XSK sockets are bound using the SKB flag instead of DRV mode.\n" \
            "--zerocopy => If set, all AF_XDP/XSK sockets are attempted to be bound with zero copy mode.\n" \
            "--copy => If set, all AF_XDP/XSK sockets are bound with copy mode.\n");

        return EXIT_SUCCESS;
    }

    // Create AF_XDP-specific command line variable and set defaults.
    struct cmd_line_af_xdp cmd_af_xdp = {0};
    cmd_af_xdp.batch_size = 1;

    // Parse AF_XDP-specific command line.
    optind = 0;
    parse_cmd_line_af_xdp(&cmd_af_xdp, argc, argv);

    // Set global variables in AF_XDP program.
    setup_af_xdp_variables(&cmd_af_xdp, cmd.verbose);

    // Check if config is specified.
    if (cmd.config == NULL)
    {
        // Copy default values.
        cmd.config = "/etc/pcktbatch/pcktbatch.yaml";

        // Let us know if we're using the default config when the verbose flag is specified.
        if (cmd.verbose)
        {
            fprintf(stdout, "No config specified. Using default: %s.\n", cmd.config);
        }
    }

    // Create config structure.
    struct config cfg = {0};
    int seq_cnt = 0;

    // Set default values on each sequence.
    for (int i = 0; i < MAX_SEQUENCES; i++)
    {
        clear_sequence(&cfg, i);
    }

    // Attempt to parse config.
    __u8 log = 1;

    if (cmd.cli)
    {
        fprintf(stdout, "Using command line...\n");
        log = 0;    
    }

    parse_config(cmd.config, &cfg, 0, &seq_cnt, log);

    if (cmd.cli)
    {
        parse_cli(&cmd, &cfg);

        seq_cnt++;
    }

    // Check for list option.
    if (cmd.list)
    {
        fprintf(stdout, "Found %d sequences.\n", seq_cnt);

        fprintf(stdout, "Got interface => %s.\n", cfg.interface);

        fprintf(stdout, "Sequences:\n\n--------------------------\n");

        for (int i = 0; i < seq_cnt; i++)
        {
            fprintf(stdout, "Sequence #%d:\n\n", i);

            fprintf(stdout, "Includes =>\n");

            if (cfg.seq[i].include_count > 0)
            {
                for (int j = 0; j < cfg.seq[i].include_count; j++)
                {
                    fprintf(stdout, "\t- %s\n", cfg.seq[i].includes[j]);
                }
            }

            fprintf(stdout, "Block => %s\n", (cfg.seq[i].block) ? "True" : "False");
            fprintf(stdout, "Count => %llu\n", cfg.seq[i].count);
            fprintf(stdout, "Time => %llu\n", cfg.seq[i].time);
            fprintf(stdout, "Delay => %llu\n", cfg.seq[i].delay);
            fprintf(stdout, "Threads => %u\n", cfg.seq[i].threads);

            fprintf(stdout, "\n\n");
        }

        return EXIT_SUCCESS;
    }

    // Loop through each sequence found.
    for (int i = 0; i < seq_cnt; i++)
    {
        seq_send(cfg.interface, cfg.seq[i], seq_cnt, cmd);
    }

    fprintf(stdout, "Completed %d sequences!\n", seq_cnt);

    // Close program successfully.
    return EXIT_SUCCESS;
}