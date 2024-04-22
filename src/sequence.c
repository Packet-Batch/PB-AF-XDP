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

#include "sequence.h"
#include "af_xdp.h"

#include <csum.h>

__u64 count[MAX_SEQUENCES];
__u64 total_data[MAX_SEQUENCES];
__u16 seq_cnt;

/**
 * The thread handler for sending/receiving.
 * 
 * @param data Data (struct thread_info) for the sequence.
 * 
 * @return Void
**/
void *thread_hdl(void *temp)
{
    // Cast data as thread info.
    struct thread_info *ti = (struct thread_info *)temp;

    // Let's parse some config values before creating the socket so we know what we're doing.
    __u8 protocol = IPPROTO_UDP;
    __u8 src_mac[ETH_ALEN] = {0};
    __u8 dst_mac[ETH_ALEN] = {0};
    __u16 data_len[MAX_PAYLOADS] = {0};
    __u16 pckt_len[MAX_PAYLOADS] = {0};

    // Payloads.
    __u8 **payloads;
    payloads = malloc(MAX_PAYLOADS * sizeof(__u8 *));
    
    if (payloads != NULL)
    {
        for (int i = 0; i < MAX_PAYLOADS; i++)
        {
            payloads[i] = malloc(MAX_PCKT_LEN * sizeof(__u8));
        }
    }
    else
    {
        fprintf(stderr, "[%d] Failed to intialize payloads array due to allocation error.\n", ti->seq_cnt);

        pthread_exit(NULL);
    }

    // Let's first start off by checking if the source MAC address is set within the config.
    if (ti->seq.eth.src_mac != NULL)
    {
        sscanf(ti->seq.eth.src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5]);
    }

    // Now check the destination MAC address.
    if (ti->seq.eth.dst_mac != NULL)
    {
        sscanf(ti->seq.eth.dst_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac[0], &dst_mac[1], &dst_mac[2], &dst_mac[3], &dst_mac[4], &dst_mac[5]);
    }

    // Now match the protocol (we exclude UDP since that's default).
    if (ti->seq.ip.protocol != NULL && !strcmp(lower_str(ti->seq.ip.protocol), "tcp"))
    {
        protocol = IPPROTO_TCP;
    }
    else if (ti->seq.ip.protocol != NULL && !strcmp(lower_str(ti->seq.ip.protocol), "icmp"))
    {
        protocol = IPPROTO_ICMP;
    }

    // Initialize socket FD.
    int sock_fd;

    // Create AF_XDP socket and check.
    sock_fd = setup_socket(ti->device, ti->id, ti->cmd.verbose);

    if (sock_fd < 0)
    {
        fprintf(stderr, "[%d] Error setting up AF_XDP socket on thread.\n", ti->seq_cnt);
        
        // Attempt to cleanup socket.
        cleanup_socket(ti->id);

        // Attempt to close the socket.
        close(sock_fd);

        pthread_exit(NULL);

        return NULL;
    }

    // Check if source MAC address is set properly. If not, let's get the MAC address of the interface we're sending packets out of.
    if (src_mac[0] == 0 && src_mac[1] == 0 && src_mac[2] == 0 && src_mac[3] == 0 && src_mac[4] == 0 && src_mac[5] == 0)
    {
        if (get_src_mac_address(ti->device, src_mac) != 0)
        {
            fprintf(stdout, "[%d] WARNING - Failed to retrieve MAC address for %s.\n", ti->seq_cnt, ti->device);
        }

        if (src_mac[0] == 0 && src_mac[1] == 0 && src_mac[2] == 0 && src_mac[3] == 0 && src_mac[4] == 0 && src_mac[5] == 0)
        {
            fprintf(stdout, "[%d] WARNING - Source MAC address retrieved is 00:00:00:00:00:00.\n", ti->seq_cnt);
        }
    }

    // Check if destination MAC is set and if not, get the default gateway's MAC address.
    if (dst_mac[0] == 0 && dst_mac[1] == 0 && dst_mac[2] == 0 && dst_mac[3] == 0 && dst_mac[4] == 0 && dst_mac[5] == 0)
    {
        // Retrieve the default gateway's MAC address and store it in dst_mac.
        get_gw_mac((__u8 *) &dst_mac);
    }

    if (ti->cmd.verbose)
    {
        printf("[%d] Source MAC address => %hhx:%hhx:%hhx:%hhx:%hhx:%hhx.\n", ti->seq_cnt, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        printf("[%d] Destination MAC address => %hhx:%hhx:%hhx:%hhx:%hhx:%hhx.\n", ti->seq_cnt, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    }

    // Create rand_r() seed.
    unsigned int seed;

    // Initialize buffer for the packet itself.
    char buffer[MAX_PCKT_LEN];

    // Common packet characteristics.
    __u8 l4_len;

    // Source IP string for a random-generated IP address.
    char s_ip[32];

    // Initialize Ethernet header.
    struct ethhdr *eth = (struct ethhdr *)(buffer);

    // Initialize IP header.
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    // Initialize UDP, TCP, and ICMP headers. Declare them as NULL until we know what protocol we're dealing with.
    struct udphdr *udph = NULL;
    struct tcphdr *tcph = NULL;
    struct icmphdr *icmph = NULL;

    // Fill out Ethernet header.
    eth->h_proto = htons(ETH_P_IP);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    memcpy(eth->h_dest, dst_mac, ETH_ALEN);

    // Fill out IP header generic fields.
    iph->ihl = 5;
    iph->version = 4;
    iph->protocol = protocol;
    iph->frag_off = 0;
    iph->tos = ti->seq.ip.tos;

    // Check for static TTL.
    if (ti->seq.ip.min_ttl == ti->seq.ip.max_ttl)
    {
        iph->ttl = ti->seq.ip.max_ttl;
    }

    // Check for static ID.
    if (ti->seq.ip.min_id == ti->seq.ip.max_id)
    {
        iph->id = htons(ti->seq.ip.max_id);
    }

    // Check for static source IP.
    if (ti->seq.ip.src_ip != NULL)
    {
        struct in_addr saddr;
        inet_aton(ti->seq.ip.src_ip, &saddr);

        iph->saddr = saddr.s_addr; 
    }

    // Destination IP.
    struct in_addr daddr;
    inet_aton(ti->seq.ip.dst_ip, &daddr);

    iph->daddr = daddr.s_addr;

    // Handle layer-4 header (UDP, TCP, or ICMP).
    switch (protocol)
    {
        case IPPROTO_UDP:
            udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
            l4_len = sizeof(struct udphdr);

            // Check for static source/destination ports.
            if (ti->seq.udp.src_port > 0)
            {
                udph->source = htons(ti->seq.udp.src_port);
            }

            if (ti->seq.udp.dst_port > 0)
            {
                udph->dest = htons(ti->seq.udp.dst_port);
            }

            break;
        
        case IPPROTO_TCP:
            tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));

            tcph->doff = 5;
            l4_len = (tcph->doff * 4);

            // Check for static source/destination ports.
            if (ti->seq.tcp.src_port > 0)
            {
                tcph->source = htons(ti->seq.tcp.src_port);
            }

            if (ti->seq.tcp.dst_port > 0)
            {
                tcph->dest = htons(ti->seq.tcp.dst_port);
            }

            // Flags.
            tcph->syn = ti->seq.tcp.syn;
            tcph->ack = ti->seq.tcp.ack;
            tcph->psh = ti->seq.tcp.psh;
            tcph->fin = ti->seq.tcp.fin;
            tcph->rst = ti->seq.tcp.rst;
            tcph->urg = ti->seq.tcp.urg;
            tcph->ece = ti->seq.tcp.ece;
            tcph->cwr = ti->seq.tcp.cwr;

            break;

        case IPPROTO_ICMP:
            icmph = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
            l4_len = sizeof(struct icmphdr);

            // Set code and type.
            icmph->code = ti->seq.icmp.code;
            icmph->type = ti->seq.icmp.type;

            break;
    }

    // Initialize payload data.
    unsigned char *data = (unsigned char *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4) + l4_len);

    // Set ending time.
    time_t end = time(NULL) + ti->seq.time;

    // Perform payload checks.
    for (int i = 0; i < ti->seq.pl_cnt; i++)
    {
        struct payload_opt *pl = &ti->seq.pls[i];
        __u8 *pl_buff = payloads[i];

        if (pl->exact != NULL)
        {
            pl->is_static = 1;
            
            char *pl_str = NULL;

            // Check if payload is file.
            if (pl->is_file)
            {
                FILE *fp = fopen(pl->exact, "rb");
                __u64 len = 0;

                // Check if our file is invalid. If so, print error and set empty payload string.
                if (fp == NULL)
                {
                    fprintf(stderr, "Unable to open payload file on payload #%d (%s) :: %s.\n", i + 1, pl->exact, strerror(errno));

                    pl_str = malloc(sizeof(char) * 2);
                    strcpy(pl_str, "");

                    goto skippayload;
                }

                // Read file and store it in payload string.
                fseek(fp, 0, SEEK_END);
                len = ftell(fp);
                fseek(fp, 0, SEEK_SET);

                pl_str = malloc(len);

                if (pl_str)
                {
                    fread(pl_str, 1, len, fp);
                }

                fclose(fp);
            }
            else
            {
                pl_str = strdup(pl->exact);
            }
            
            skippayload:;

            // Check if we want to parse the actual string.
            if (pl->is_string)
            {
                data_len[i] = strlen(pl_str);

                memcpy(pl_buff, pl_str, data_len[i]);
            }
            else
            {
                // Split argument by space.
                char *split;
                char *rest = pl_str;

                while ((split = strtok_r(rest, " ", &rest)))
                {
                    sscanf(split, "%2hhx", &pl_buff[data_len[i]]);

                    data_len[i]++;
                }
            }

            // Set packet length now.
            pckt_len[i] = sizeof(struct ethhdr) + (iph->ihl * 4) + l4_len + data_len[i];

            free(pl_str);
        }
        else if (pl->is_static)
        {
            // Generate random payload between a range if needed.
            if (pl->max_len > 0)
            {
                // Calculate a random length
                data_len[i] = rand_num(pl->min_len, pl->max_len, seed);
                pckt_len[i] = sizeof(struct ethhdr) + (iph->ihl * 4) + l4_len + data_len[i];

                // Fill out payload with random characters.
                for (__u16 i = 0; i < data_len[i]; i++)
                {
                    *(pl_buff + i) = rand_r(&seed);
                }
            }
            else
            {
                // 0 bytes of payload.
                data_len[i] = 0;
                pckt_len[i] = sizeof(struct ethhdr) + (iph->ihl * 4) + l4_len;
            }
        }
    }

    // If we have no payloads, set to an empty payload.
    if (ti->seq.pl_cnt < 1)
    {
        ti->seq.pl_cnt = 1;

        struct payload_opt *pl = &ti->seq.pls[0];
        pl->is_static = 1;

        // Calculate lengths.
        data_len[0] = 0;
        pckt_len[0] = sizeof(struct ethhdr) + (iph->ihl * 4) + l4_len;
    }

    // Loop.
    while (1)
    {
        // Generate seed for random integers.
        seed = time(NULL) ^ count[ti->seq_cnt];

        // Check for random TTL.
        if (ti->seq.ip.min_ttl != ti->seq.ip.max_ttl)
        {
            iph->ttl = rand_num(ti->seq.ip.min_ttl, ti->seq.ip.max_ttl, seed);
        }

        // Check for random ID.
        if (ti->seq.ip.min_id != ti->seq.ip.max_id)
        {
            iph->id = htons(rand_num(ti->seq.ip.min_id, ti->seq.ip.max_id, seed));
        }

        // Check if source IP is defined. If not, get a random IP from the ranges and assign it to the IP header's source IP.
        if (ti->seq.ip.src_ip == NULL)
        {
            // Check if there are ranges.
            if (ti->seq.ip.range_count > 0)
            {
                __u16 ran = rand_num(0, (ti->seq.ip.range_count - 1), seed);

                // Ensure this range is valid.
                if (ti->seq.ip.ranges[ran] != NULL)
                {
                    if (ti->seq.max_count < 1 && !ti->seq.track_count)
                    {
                        count[ti->seq_cnt]++;
                    }
    
                    char *randip = rand_ip(ti->seq.ip.ranges[ran], &count[ti->seq_cnt]);

                    if (randip != NULL)
                    {
                        strcpy(s_ip, randip);
                    }
                    else
                    {
                        goto fail;
                    }
                }
                else
                {
                    fail:
                    fprintf(stderr, "[%d] ERROR - Source range count is above 0, but string is NULL. Please report this! Using localhost...\n", ti->seq_cnt);

                    strcpy(s_ip, "127.0.0.1");
                }
            }
            else
            {
                // This shouldn't happen, but since it did, just assign localhost and warn the user.
                fprintf(stdout, "[%d] WARNING - No source IP or source range(s) specified. Using localhost...\n", ti->seq_cnt);

                strcpy(s_ip, "127.0.0.1");
            }

            // Copy 32-bit IP address to IP header in network byte order.
            struct in_addr s_addr;
            inet_aton(s_ip, &s_addr);

            iph->saddr = s_addr.s_addr;
        }

        // Check layer-4 protocols and assign random characteristics if need to be.
        if (protocol == IPPROTO_UDP)
        {
            // Check for random source port.
            if (ti->seq.udp.src_port == 0)
            {
                udph->source = htons(rand_num(1, 65535, seed));
            }

            // Check for random destination port.
            if (ti->seq.udp.dst_port == 0)
            {
                udph->dest = htons(rand_num(1, 65535, seed));
            }
        }
        else if (protocol == IPPROTO_TCP)
        {
            if (ti->seq.tcp.src_port == 0)
            {
                tcph->source = htons(rand_num(1, 65535, seed));
            }

            if (ti->seq.tcp.dst_port == 0)
            {
                tcph->dest = htons(rand_num(1, 65535, seed));
            }
        }

        // Loop through each payload.
        for (int i = 0; i < ti->seq.pl_cnt; i++)
        {
            struct payload_opt *pl = &ti->seq.pls[i];

            // Check if we need to calculate random payload.
            if (pl->is_static)
            {
                if (data_len[i] > 0)
                {
                    memcpy(data, payloads[i], data_len[i]);
                }
            }
            else
            {
                if (pl->max_len > 0)
                {
                    // Recalculate length to random.
                    data_len[i] = rand_num(pl->min_len, pl->max_len, seed);
                    pckt_len[i] = sizeof(struct ethhdr) + (iph->ihl * 4) + l4_len + data_len[i];

                    // Fill out payload with random characters.
                    for (__u16 i = 0; i < data_len[i]; i++)
                    {
                        *(data + i) = rand_r(&seed);
                    }
                }
                else if (pckt_len[i] < 1)
                {
                    pckt_len[i] = sizeof(struct ethhdr) + (iph->ihl * 4) + l4_len + data_len[i];
                }
            }

            // Perform checksum and length calculations for layer-4 headers.
            switch (iph->protocol)
            {
                case IPPROTO_UDP:
                    udph->len = htons(sizeof(struct udphdr) + data_len[i]);
                    
                    if (ti->seq.l4_csum)
                    {
                        udph->check = 0;
                        udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4_len + data_len[i], IPPROTO_UDP, csum_partial(udph, l4_len + data_len[i], 0));
                    }

                    break;

                case IPPROTO_TCP:
                    if (ti->seq.l4_csum)
                    {
                        tcph->check = 0;
                        tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4_len + data_len[i], IPPROTO_TCP, csum_partial(tcph, l4_len + data_len[i], 0));
                    }

                    break;

                case IPPROTO_ICMP:
                    if (ti->seq.l4_csum)
                    {
                        icmph->checksum = 0;
                        icmph->checksum = icmp_csum((__u16 *)icmph, l4_len + data_len[i]);
                    }

                    break;
            }

            // Calculate IP header total length and checksum if necessary.
            iph->tot_len = htons((iph->ihl * 4) + l4_len + data_len[i]);

            if (ti->seq.ip.csum)
            {
                update_iph_checksum(iph);
            }

            // Send packet out.
            int ret = 0;

            /*
            if ((ret = send_packet(ti->id, buffer, pckt_len[i], ti->cmd.verbose)) != 0)
            {
                fprintf(stderr, "ERROR - Could not send packet on AF_XDP socket (%d) :: %s.\n", ti->id, strerror(errno));
            }
            */

            // Check if we want to send verbose output or not.
            if (ti->cmd.verbose && ret == 0)
            {
                // Retrieve source and destination ports for UDP/TCP protocols.
                __u16 srcport = 0;
                __u16 dstport = 0;

                if (protocol == IPPROTO_UDP)
                {
                    srcport = ntohs(udph->source);
                    dstport = ntohs(udph->dest);
                }
                else if (protocol == IPPROTO_TCP)
                {
                    srcport = ntohs(tcph->source);
                    dstport = ntohs(tcph->dest);
                }

                fprintf(stdout, "[%d][%d] Sent %d bytes of data from %s:%d to %s:%d.\n", ti->seq_cnt, i + 1, pckt_len[i], (ti->seq.ip.src_ip != NULL) ? ti->seq.ip.src_ip : s_ip, srcport, ti->seq.ip.dst_ip, dstport);
            }

            // Increment total bytes for sequence so far.
            __sync_add_and_fetch(&total_data[ti->seq_cnt], pckt_len[i]);
        }

        // Check packet count.
        if (ti->seq.max_count > 0 || ti->seq.track_count)
        {
            // Increment current count.
            __sync_add_and_fetch(&count[ti->seq_cnt], 1);

            // Check if we should break.
            if (ti->seq.max_count > 0 && count[ti->seq_cnt] >= ti->seq.max_count)
            {
                fprintf(stdout, "[%d] Packet count exceeded for sequence. Stopping...\n", ti->seq_cnt);

                break;
            }            
        }

        // Check time.
        if (ti->seq.time > 0 && time(NULL) >= end)
        {
            fprintf(stdout, "[%d] Time exceeded for sequence. Stopping...\n", ti->seq_cnt);

            break;
        }

        // Check data.
        if (ti->seq.max_data > 0)
        {
            if (total_data[ti->seq_cnt] >= ti->seq.max_data)
            {
                fprintf(stdout, "[%d] Max data exceeded for sequence. Stopping...\n", ti->seq_cnt);

                break;
            }
        }

        // Check for delay.
        if (ti->seq.delay > 0)
        {
            usleep(ti->seq.delay);
        }
    }

    // Cleanup AF_XDP socket.
    cleanup_socket(ti->id);

    // Attempt to close the socket.
    close(sock_fd);
    
    // Free payloads.
    free(payloads);

    pthread_exit(NULL);
}

/**
 * Starts a sequence in send mode. 
 * 
 * @param interface The networking interface to send packets out of.
 * @param seq A singular sequence structure containing relevant information for the packet.
 * @param seq_cnt2 The sequence counter from the main program.
 * @param cmd The command line structure.
 * 
 * @return Void
**/
void seq_send(const char *interface, struct sequence seq, __u16 seq_cnt2, struct cmd_line cmd)
{
    // First, let's check if the destination IP is set.
    if (seq.ip.dst_ip == NULL)
    {
        fprintf(stdout, "Destination IP not set on sequence #%u. Not moving forward with this sequence.\n", seq_cnt2);

        return;
    }

    // Create new thread_info structure to pass to threads.
    struct thread_info ti = {0};

    // Assign correct values to thread info.
    strcpy((char *)&ti.device, interface);
    memcpy(&ti.seq, &seq, sizeof(struct sequence));

    // Copy command line.
    ti.cmd = cmd;

    // Create the threads needed.
    int threads = (seq.threads > 0) ? seq.threads : get_nprocs();

    // Reset count and total data for this sequence.
    count[seq_cnt] = 0;
    total_data[seq_cnt] = 0;

    ti.seq_cnt = seq_cnt2;

    pthread_t p_id[MAX_THREADS];

    for (int i = 0; i < threads; i++)
    {
        ti.id = i;

        // Create a duplicate of thread info structure to send to each thread.
        struct thread_info *ti_dup = malloc(sizeof(struct thread_info));
        memcpy(ti_dup, &ti, sizeof(struct thread_info));

        pthread_create(&p_id[i], NULL, thread_hdl, (void *)ti_dup);
    }

    // Check for block or if this is the last sequence (we'd want to join threads so the main thread exits after completion).
    if (seq.block || (seq_cnt) >= (seq_cnt2 - 1))
    {
        for (int i = 0; i < threads; i++)
        {
            pthread_join(p_id[i], NULL);
        }
    }

    seq_cnt++;
}