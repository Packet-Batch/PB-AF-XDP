#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <getopt.h>
#include <errno.h>

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

        // Make sure we have at least one sequence.
        if (seq_cnt < 1)
            seq_cnt = 1;
    }

    // Check for list option. If so, print helpful information for configuration.
    if (cmd.list)
    {
        fprintf(stdout, "Found %d sequences.\n", seq_cnt);

        fprintf(stdout, "Got interface => %s.\n", cfg.interface ? cfg.interface : "N/A");

        fprintf(stdout, "Sequences:\n\n--------------------------\n");

        for (int i = 0; i < seq_cnt; i++)
        {
            struct sequence *seq = &cfg.seq[i];

            if (!seq)
                continue;

            fprintf(stdout, "Sequence #%d:\n", i);

            // General settings.
            fprintf(stdout, "\tGeneral\n");
            fprintf(stdout, "\t\tIncludes =>\n");

            if (seq->include_count > 0)
            {
                for (int j = 0; j < seq->include_count; j++)
                {
                    fprintf(stdout, "\t\t\t- %s\n", seq->includes[j]);
                }
            }


            fprintf(stdout, "\t\tInterface Override => %s\n", seq->interface ? seq->interface : "N/A");
            fprintf(stdout, "\t\tBlock => %s\n", seq->block ? "True" : "False");
            fprintf(stdout, "\t\tCount => %llu\n", seq->count);
            fprintf(stdout, "\t\tTime => %llu\n", seq->time);
            fprintf(stdout, "\t\tDelay => %llu\n", seq->delay);
            fprintf(stdout, "\t\tThreads => %u\n", seq->threads);

            // Ethernet settings.
            fprintf(stdout, "\tEthernet\n");
            fprintf(stdout, "\t\tSource MAC => %s\n", seq->eth.src_mac ? seq->eth.src_mac : "N/A");
            fprintf(stdout, "\t\tDestination MAC => %s\n", seq->eth.dst_mac ? seq->eth.dst_mac : "N/A");

            // IP settings.
            fprintf(stdout, "\tIP\n");
            fprintf(stdout, "\t\tProtocol => %s\n", seq->ip.protocol ? seq->ip.protocol : "N/A");

            fprintf(stdout, "\t\tSource IP => %s\n", seq->ip.src_ip ? seq->ip.src_ip : "N/A");
            fprintf(stdout, "\t\tDestination IP => %s\n", seq->ip.dst_ip ? seq->ip.dst_ip : "N/A");

            if (seq->ip.range_count > 0)
            {
                for (int j = 0; j < seq->ip.range_count; j++)
                    fprintf(stdout, "\t\t\t- %s\n", seq->ip.ranges[j]);
            }

            fprintf(stdout, "\t\tType of Service => %d\n", seq->ip.tos);
            fprintf(stdout, "\t\tMin TTL => %d\n", seq->ip.min_ttl);
            fprintf(stdout, "\t\tMax TTL => %d\n", seq->ip.max_ttl);
            fprintf(stdout, "\t\tMin ID => %d\n", seq->ip.min_id);
            fprintf(stdout, "\t\tMax ID => %d\n", seq->ip.max_id);
            fprintf(stdout, "\t\tChecksum => %s\n", seq->ip.csum ? "Yes" : "No");

            // TCP settings.
            fprintf(stdout, "\tTCP\n");
            fprintf(stdout, "\t\tSource Port => %d\n", seq->tcp.src_port);
            fprintf(stdout, "\t\tDest Port => %d\n", seq->tcp.dst_port);
            fprintf(stdout, "\t\tUse Socket => %s\n", seq->tcp.use_socket ? "Yes" : "No");
            fprintf(stdout, "\t\tSYN Flag => %s\n", seq->tcp.syn ? "Yes": "No");
            fprintf(stdout, "\t\tPSH Flag => %s\n", seq->tcp.psh ? "Yes" : "No");
            fprintf(stdout, "\t\tFIN Flag => %s\n", seq->tcp.fin ? "Yes" : "No");
            fprintf(stdout, "\t\tACK Flag => %s\n", seq->tcp.ack ? "Yes" : "No");
            fprintf(stdout, "\t\tRST Flag => %s\n", seq->tcp.rst ? "Yes" : "No");
            fprintf(stdout, "\t\tURG Flag => %s\n", seq->tcp.urg ? "Yes" : "No");

            // UDP settings.
            fprintf(stdout, "\tUDP\n");
            fprintf(stdout, "\t\tSrc Port => %d\n", seq->udp.src_port);
            fprintf(stdout, "\t\tDst Port => %d\n", seq->udp.dst_port);

            // ICMP settings.
            fprintf(stdout, "\tICMP\n");
            fprintf(stdout, "\t\tCode => %d\n", seq->icmp.code);
            fprintf(stdout, "\t\tType => %d\n", seq->icmp.type);

            // Layer 4 setting(s).
            fprintf(stdout, "\tLayer 4\n");
            fprintf(stdout, "\t\tChecksum => %s\n", seq->l4_csum ? "Yes" : "No");

            // Payload settings.
            fprintf(stdout, "\tPayload\n");
            fprintf(stdout, "\t\tMin Length => %d\n", seq->pl.min_len);
            fprintf(stdout, "\t\tMax Length => %d\n", seq->pl.max_len);
            fprintf(stdout, "\t\tIs Static => %s\n", seq->pl.is_static ? "Yes" : "No");
            fprintf(stdout, "\t\tIs File => %s\n", seq->pl.is_file ? "Yes" : "No");
            fprintf(stdout, "\t\tIs String => %s\n", seq->pl.is_string ? "Yes" : "No");
            fprintf(stdout, "\t\tExact String => %s\n", seq->pl.exact ? seq->pl.exact : "N/A");

            fprintf(stdout, "\n\n");
        }

        return EXIT_SUCCESS;
    }

    // Before continuing, if we're in shared UMEM mode, create the first and only UMEM before going to each thread to avoid concurrency issues.
    if (cmd_af_xdp.shared_umem)
    {
        if (setup_umem(0) != 0)
        {
            fprintf(stderr, "Error creating shared UMEM :: %s (%d).\n", strerror(-errno), errno);

            return EXIT_FAILURE;
        }
    }

    // Loop through each sequence found.
    for (int i = 0; i < seq_cnt; i++)
    {
        seq_send(cfg.interface, cfg.seq[i], seq_cnt, cmd);
    }

    // Print number of sequences completed at end.
    fprintf(stdout, "Completed %d sequences!\n", seq_cnt);

    // Close program successfully.
    return EXIT_SUCCESS;
}