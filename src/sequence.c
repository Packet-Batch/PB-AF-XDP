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

#include <utils.h>
#include <cmd_line.h>
#include <config.h>

#include "sequence.h"

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
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];
    __u8 payload[MAX_PCKT_LEN];
    __u16 exact_pl_len = 0;
    __u16 data_len;

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

    // Now check for the payload.
    if (ti->seq.pl.exact != NULL)
    {
        char *pl_str = NULL;

        // Check if payload is file.
        if (ti->seq.pl.is_file)
        {
            FILE *fp = fopen(ti->seq.pl.exact, "rb");
            __u64 len = 0;

            // Check if our file is invalid. If so, print error and set empty payload string.
            if (fp == NULL)
            {
                fprintf(stderr, "Unable to open payload file (%s) :: %s.\n", ti->seq.pl.exact, strerror(errno));

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
            pl_str = strdup(ti->seq.pl.exact);
        }
        
        skippayload:;

        // Check if we want to parse the actual string.
        if (ti->seq.pl.is_string)
        {
            exact_pl_len = strlen(pl_str);

            memcpy(payload, pl_str, exact_pl_len);
        }
        else
        {
            // Split argument by space.
            char *split;
            char *rest = pl_str;

            while ((split = strtok_r(rest, " ", &rest)))
            {
                sscanf(split, "%2hhx", &payload[exact_pl_len]);
                
                exact_pl_len++;
            }
        }

        free(pl_str);
    }

    // Create sockaddr_ll struct.
    struct sockaddr_ll sin;

    // Fill out sockaddr_ll struct.
    sin.sll_family = PF_PACKET;
    sin.sll_ifindex = if_nametoindex((ti->seq.interface != NULL) ? ti->seq.interface : ti->device);
    sin.sll_protocol = htons(ETH_P_IP);
    sin.sll_halen = ETH_ALEN;

    // Initialize socket FD.
    int sock_fd;

    // Attempt to create socket and also check for TCP cooked socket.
    __u8 sock_domain = AF_PACKET;
    __u8 sock_type = SOCK_RAW;
    __u8 sock_proto = IPPROTO_RAW;

    if (protocol == IPPROTO_TCP && ti->seq.tcp.use_socket)
    {
        sock_domain = AF_INET;
        sock_type = SOCK_STREAM;
        sock_proto = 0;
    }

    if ((protocol != IPPROTO_TCP || !ti->seq.tcp.use_socket) && (sock_fd = socket(sock_domain, sock_type, sock_proto)) < 0)
    {
        fprintf(stderr, "ERROR - Could not setup socket :: %s.\n", strerror(errno));

        pthread_exit(NULL);
    }

    // Check if source MAC address is set properly. If not, let's get the MAC address of the interface we're sending packets out of.
    if (src_mac[0] == 0 && src_mac[1] == 0 && src_mac[2] == 0 && src_mac[3] == 0 && src_mac[4] == 0 && src_mac[5] == 0 && !ti->seq.tcp.use_socket)
    {
        // Receive the interface's MAC address (the source MAC).
        struct ifreq if_req;
        
        strcpy(if_req.ifr_name, (ti->seq.interface != NULL) ? ti->seq.interface : ti->device);

        // Attempt to get MAC address.
        if (ioctl(sock_fd, SIOCGIFHWADDR, &if_req) != 0)
        {
            fprintf(stderr, "ERROR - Could not retrieve MAC address of interface :: %s.\n", strerror(errno));

            pthread_exit(NULL);
        }

        // Copy source MAC to necessary variables.
        memcpy(src_mac, if_req.ifr_addr.sa_data, ETH_ALEN);
    }

    memcpy(sin.sll_addr, src_mac, ETH_ALEN);

    // Check if destination MAC is set and if not, get the default gateway's MAC address.
    if (dst_mac[0] == 0 && dst_mac[1] == 0 && dst_mac[2] == 0 && dst_mac[3] == 0 && dst_mac[4] == 0 && dst_mac[5] == 0)
    {
        // Retrieve the default gateway's MAC address and store it in dst_mac.
        get_gw_mac((__u8 *) &dst_mac);
    }

    if (protocol != IPPROTO_TCP || !ti->seq.tcp.use_socket)
    {
        // Attempt to bind socket.
        if (bind(sock_fd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
        {
            fprintf(stderr, "ERROR - Cannot bind to socket :: %s.\n", strerror(errno));

            pthread_exit(NULL);
        }
    }
    /* Our goal below is to set as many things before the while loop as possible since any additional instructions inside the while loop will impact performance. */

    // Some variables to help decide the randomness of our packets.
    __u8 need_csum = 1;
    __u8 need_l4_csum = 1;
    __u8 need_len_recal = 1;

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

            // If we have static/same payload length, let's set the UDP header's length here.
            if (exact_pl_len > 0 || ti->seq.pl.min_len == ti->seq.pl.max_len)
            {
                data_len = (exact_pl_len > 0) ? exact_pl_len : ti->seq.pl.max_len;

                udph->len = htons(l4_len + data_len);

                // If we have static payload length/data or our source/destination IPs/ports are static, we can calculate the UDP header's outside of while loop.
                if ((ti->seq.udp.src_port > 0 && ti->seq.udp.dst_port > 0 && ti->seq.ip.src_ip != NULL) && exact_pl_len > 0)
                {
                    need_l4_csum = 0;
                }

                need_len_recal = 0;
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

            // Check if we need to do length recalculation later on.
            if (exact_pl_len > 0 || ti->seq.pl.min_len == ti->seq.pl.max_len)
            {
                data_len = (exact_pl_len > 0) ? exact_pl_len : ti->seq.pl.max_len;

                need_len_recal = 0;
            }

            // If we have static payload length/data or our source/destination IPs/ports are static, we can calculate the TCP header's checksum here.
            if (!need_len_recal && (ti->seq.tcp.src_port > 0 && ti->seq.tcp.dst_port > 0 && ti->seq.ip.src_ip != NULL) && exact_pl_len > 0)
            {
                need_l4_csum = 0;
            }

            break;

        case IPPROTO_ICMP:
            icmph = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
            l4_len = sizeof(struct icmphdr);

            // Set code and type.
            icmph->code = ti->seq.icmp.code;
            icmph->type = ti->seq.icmp.type;

            // If we have static payload length/data, we can calculate the ICMP header's checksum outside of while loop.
            if (exact_pl_len > 0 || ti->seq.pl.min_len == ti->seq.pl.max_len)
            {
                data_len = (exact_pl_len > 0) ? exact_pl_len : ti->seq.pl.max_len;

                need_len_recal = 0;

                if (exact_pl_len > 0)
                {
                    need_l4_csum = 0;
                }
            }

            break;
    }

    // Check if we can set static IP header length.
    if (!need_len_recal)
    {
        iph->tot_len = htons((iph->ihl * 4) + l4_len + data_len);
    }

    // Check if we need to calculate the IP checksum later on or not. If not, calculate now.
    if (ti->seq.ip.min_ttl == ti->seq.ip.max_ttl && ti->seq.ip.min_id == ti->seq.ip.max_id && ti->seq.ip.src_ip != NULL && !need_len_recal)
    {
        need_csum = 0;

        if (ti->seq.ip.csum)
        {
            update_iph_checksum(iph);
        }
    }

    // Initialize payload data.
    unsigned char *data = (unsigned char *)(buffer + sizeof(struct ethhdr) + (iph->ihl * 4) + l4_len);

    // Check for exact payload.
    if (exact_pl_len > 0)
    {
        for (__u16 i = 0; i < exact_pl_len; i++)
        {
            *(data + i) = payload[i];
        }

        // Calculate UDP and ICMP header's checksums.
        if (!need_l4_csum && protocol == IPPROTO_UDP && ti->seq.l4_csum)
        {
            udph->check = 0;
            udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4_len + data_len, IPPROTO_UDP, csum_partial(udph, l4_len + data_len, 0));
        }
        else if (!need_l4_csum && protocol == IPPROTO_TCP && ti->seq.l4_csum)
        {
            tcph->check = 0;
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (tcph->doff * 4) + data_len, IPPROTO_TCP, csum_partial(tcph, (tcph->doff * 4) + data_len, 0));
        }
        else if (!need_l4_csum && protocol == IPPROTO_ICMP && ti->seq.l4_csum)
        {
            icmph->checksum = 0;
            icmph->checksum = icmp_csum((__u16 *)icmph, l4_len + data_len);
        }
    }

    // Check for static payload.
    if (exact_pl_len < 1 && ti->seq.pl.is_static)
    {
        data_len = rand_num(ti->seq.pl.min_len, ti->seq.pl.max_len, seed);

        // Fill out payload with random characters.
        for (__u16 i = 0; i < data_len; i++)
        {
            *(data + i) = rand_r(&seed);
        }

        // Recalculate UDP/ICMP checksums and ensure we don't calculate them again in while loop since we don't need to (will improve performance).
        if (!need_len_recal)
        {
            if (protocol == IPPROTO_UDP && ti->seq.l4_csum)
            {
                udph->check = 0;
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4_len + data_len, IPPROTO_UDP, csum_partial(udph, l4_len + data_len, 0));
            }
            if (protocol == IPPROTO_TCP && ti->seq.l4_csum)
            {
                tcph->check = 0;
                tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (tcph->doff * 4) + data_len, IPPROTO_TCP, csum_partial(tcph, (tcph->doff * 4) + data_len, 0));
            }
            else if (protocol == IPPROTO_ICMP && ti->seq.l4_csum)
            {
                icmph->checksum = 0;
                icmph->checksum = icmp_csum((__u16 *)icmph, l4_len + data_len);
            }

            need_l4_csum = 0;
        }
    }

    // Set ending time.
    time_t end = time(NULL) + ti->seq.time;

    // Setup TCP cooked socket information.
    struct sockaddr_in tcpsin;
    tcpsin.sin_family = AF_INET;

    struct in_addr tdaddr;
    inet_aton(ti->seq.ip.dst_ip, &tdaddr);

    tcpsin.sin_addr.s_addr = tdaddr.s_addr;
    tcpsin.sin_port = htons(ti->seq.tcp.dst_port);
    memset(&tcpsin.sin_zero, 0, sizeof(tcpsin.sin_zero));

    // Loop.
    while (1)
    {
        // Increase count and check.
        if (ti->seq.count > 0 || ti->seq.track_count)
        {
            if (ti->seq.count > 0 && count[ti->seq_cnt] >= ti->seq.count)
            {
                break;
            }

            __sync_add_and_fetch(&count[ti->seq_cnt], 1);
        }

        // Check time.
        if (ti->seq.time > 0 && time(NULL) >= end)
        {
            break;
        }

        seed = time(NULL) ^ count[ti->seq_cnt];

        /* Assign random IP header values if need to be. */

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
        if (ti->seq.ip.src_ip == NULL && !ti->seq.tcp.use_socket)
        {
            // Check if there are ranges.
            if (ti->seq.ip.range_count > 0)
            {
                __u16 ran = rand_num(0, (ti->seq.ip.range_count - 1), seed);

                // Ensure this range is valid.
                if (ti->seq.ip.ranges[ran] != NULL)
                {
                    if (ti->seq.count < 1 && !ti->seq.track_count)
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
                    fprintf(stderr, "ERROR - Source range count is above 0, but string is NULL. Please report this! Using localhost...\n");

                    strcpy(s_ip, "127.0.0.1");
                }
            }
            else
            {
                // This shouldn't happen, but since it did, just assign localhost and warn the user.
                fprintf(stdout, "WARNING - No source IP or source range(s) specified. Using localhost...\n");

                strcpy(s_ip, "127.0.0.1");
            }

            // Copy 32-bit IP address to IP header in network byte order.
            struct in_addr s_addr;
            inet_aton(s_ip, &s_addr);

            iph->saddr = s_addr.s_addr;
        }
        
        // Check if we need to calculate random payload.
        if (exact_pl_len < 1 && !ti->seq.pl.is_static)
        {
            data_len = rand_num(ti->seq.pl.min_len, ti->seq.pl.max_len, seed);

            // Fill out payload with random characters.
            for (__u16 i = 0; i < data_len; i++)
            {
                *(data + i) = rand_r(&seed);
            }
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

            // Check for UDP length recalculation.
            if (need_len_recal)
            {
                udph->len = htons(l4_len + data_len);
            }

            // Check for UDP checksum recalculation.
            if (need_l4_csum && ti->seq.l4_csum)
            {
                udph->check = 0;
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, sizeof(struct udphdr) + data_len, IPPROTO_UDP, csum_partial(udph, sizeof(struct udphdr) + data_len, 0));   
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

            // Check if we need to calculate checksum.
            if (need_l4_csum && ti->seq.l4_csum)
            {
                tcph->check = 0;
                tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (tcph->doff * 4) + data_len, IPPROTO_TCP, csum_partial(tcph, (tcph->doff * 4) + data_len, 0));   
            }

            if (ti->seq.tcp.use_socket)
            {
                if ((sock_fd = socket(sock_domain, sock_type, sock_proto)) < 0)
                {
                    fprintf(stderr, "ERROR - Cannot setup TCP cook socket :: %s.\n", strerror(errno));

                    pthread_exit(NULL);
                }

                if (connect(sock_fd, (struct sockaddr *)&tcpsin, sizeof(tcpsin)) != 0)
                {
                    fprintf(stderr, "ERROR - Cannot connect to destination using cooked sockets :: %s.\n", strerror(errno));

                    pthread_exit(NULL);
                }
            }
        }
        else if (protocol == IPPROTO_ICMP)
        {
            if (need_l4_csum && ti->seq.l4_csum)
            {
                icmph->checksum = 0;
                icmph->checksum = icmp_csum((__u16 *)icmph, l4_len + data_len);
            }
        }
        
        // Check for length recalculation for IP header.
        if (need_len_recal)
        {
            iph->tot_len = htons((iph->ihl * 4) + l4_len + data_len);
        }

        // Check if we need to calculate IP checksum.
        if (need_csum && ti->seq.ip.csum)
        {
            update_iph_checksum(iph);
        }

        __u16 sent;

        // Attempt to send packet.
        if (protocol == IPPROTO_TCP && ti->seq.tcp.use_socket)
        {
            if ((sent = send(sock_fd, data, data_len, 0)) < 0)
            {
                fprintf(stderr, "ERROR - Could not send TCP (cooked) packet with length %hu :: %s.\n", (ntohs(iph->tot_len)), strerror(errno));
            }
        }
        else
        {
            if ((sent = send(sock_fd, buffer, ntohs(iph->tot_len) + sizeof(struct ethhdr), 0)) < 0)
            {
                fprintf(stderr, "ERROR - Could not send packet with length %lu :: %s.\n", (ntohs(iph->tot_len) + sizeof(struct ethhdr)), strerror(errno));
            }
        }

        // Check if we want to send verbose output or not.
        if (ti->cmd.verbose && sent > 0)
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

            fprintf(stdout, "Sent %d bytes of data from %s:%d to %s:%d.\n", sent, (ti->seq.ip.src_ip != NULL) ? ti->seq.ip.src_ip : s_ip, srcport, ti->seq.ip.dst_ip, dstport);
        }

        // Check data.
        if (ti->seq.max_data > 0)
        {
            if (total_data[ti->seq_cnt] >= ti->seq.max_data)
            {
                break;
            }

            __sync_add_and_fetch(&total_data[ti->seq_cnt], ntohs(iph->tot_len) + sizeof(struct ethhdr));
        }

        // Close TCP socket if enabled.
        if (ti->seq.tcp.use_socket)
        {
            close(sock_fd);
        }

        // Check for delay.
        if (ti->seq.delay > 0)
        {
            usleep(ti->seq.delay);
        }
    }

    // Close socket.
    if (!ti->seq.tcp.use_socket)
    {
        close(sock_fd);
    }

    pthread_exit(NULL);
}

/**
 * Starts a sequence in send mode. 
 * 
 * @param interface The networking interface to send packets out of.
 * @param seq A singular sequence structure containing relevant information for the packet.
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