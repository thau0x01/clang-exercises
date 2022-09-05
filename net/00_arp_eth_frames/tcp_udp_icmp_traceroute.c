// Perform a traceroute by sending IPv4 TCP, UDP, or ICMP packets via
// raw socket at the link layer (ethernet frame).
// Need to have destination MAC address.
// TCP set for SYN, UDP for port unreachable, ICMP for echo request (ping).

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>           // struct addrinfo
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>      // needed for socket()
#include <netinet/in.h>      // IPPROTO_RAW, IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>      // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h> // struct icmp and ICMP_TIME_EXCEEDED
#define __FAVOR_BSD          // Use BSD format of TCP header and UDP header
#include <netinet/tcp.h>     // struct tcphdr
#include <netinet/udp.h>     // struct udphdr
#include <fcntl.h>           // fcntl()
#include <sys/select.h>      // select()
#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl.
#include <net/if.h>          // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <sys/time.h> // gettimeofday()

#include <errno.h> // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP4_HDRLEN 20 // IPv4 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data
#define UDP_HDRLEN 8  // UDP header length, excludes data
#define ICMP_HDRLEN 8 // ICMP header length for echo request, excludes data
#define TIMEOUT 2     // Time for receive socket to wait for a reply (s)

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t tcp4_checksum(struct ip, struct tcphdr, uint8_t *, int);
uint16_t udp4_checksum(struct ip, struct udphdr, uint8_t *, int);
uint16_t icmp4_checksum(struct icmp, uint8_t *, int);
int create_tcp_frame(uint8_t *, char *, char *, uint8_t *, uint8_t *, int, uint8_t *, int);
int create_udp_frame(uint8_t *, char *, char *, uint8_t *, uint8_t *, int, uint8_t *, int);
int create_icmp_frame(uint8_t *, char *, char *, uint8_t *, uint8_t *, int, uint8_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

int main(int argc, char **argv)
{

    int i, status, frame_length, sd, sendsd, recsd, bytes, flags, node, trylim, trycount;
    int packet_type, done, datalen, resolve, maxhops, probes, num_probes;
    char *interface, *target, *src_ip, *dst_ip, *rec_ip, *tcp_dat, *icmp_dat, *udp_dat;
    char hostname[NI_MAXHOST];
    struct ip *iphdr;
    struct tcphdr *tcphdr;
    struct icmp *icmphdr;
    uint8_t *src_mac, *dst_mac;
    uint8_t *snd_ether_frame, *rec_ether_frame;
    uint8_t *data;
    struct addrinfo hints, *res;
    struct sockaddr_in *dst, sa;
    struct sockaddr from;
    struct sockaddr_ll device;
    struct ifreq ifr;
    socklen_t fromlen;
    struct timeval wait, t1, t2;
    struct timezone tz;
    fd_set rset;
    double dt;
    void *tmp;

    // Choose whether to resolve IPs to hostnames: 0 = do not resolve, 1 = resolve
    resolve = 0;

    // Number of probes per node.
    num_probes = 3;

    // Choose type of packet to send: 1 = TCP, 2 = ICMP, 3 = UDP
    packet_type = 1;

    // Maximum number of hops allowed.
    maxhops = 30;

    // Allocate memory for various arrays.
    tcp_dat = allocate_strmem(IP_MAXPACKET);
    icmp_dat = allocate_strmem(IP_MAXPACKET);
    udp_dat = allocate_strmem(IP_MAXPACKET);
    data = allocate_ustrmem(IP_MAXPACKET);
    rec_ip = allocate_strmem(INET_ADDRSTRLEN);
    src_mac = allocate_ustrmem(6);
    dst_mac = allocate_ustrmem(6);
    snd_ether_frame = allocate_ustrmem(IP_MAXPACKET);
    rec_ether_frame = allocate_ustrmem(IP_MAXPACKET);
    interface = allocate_strmem(40);
    target = allocate_strmem(40);
    src_ip = allocate_strmem(INET_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET_ADDRSTRLEN);

    // Payloads for TCP, UDP, and ICMP packets.
    strcpy(tcp_dat, "");
    strcpy(icmp_dat, "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_"); // Seems to be commonly used, but unnecessary I think
    strcpy(udp_dat, "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_");  // Seems to be commonly used, but unnecessary I think

    // Check for acceptable payload lengths.
    if (strlen(tcp_dat) > (IP_MAXPACKET - IP4_HDRLEN - TCP_HDRLEN))
    {
        fprintf(stderr, "Maximum TCP data length exceeded. Maximum length is %i\n", IP_MAXPACKET - IP4_HDRLEN - TCP_HDRLEN);
        exit(EXIT_FAILURE);
    }
    if (strlen(icmp_dat) > (IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN))
    {
        fprintf(stderr, "Maximum ICMP data length exceeded. Maximum length is %i\n", IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN);
        exit(EXIT_FAILURE);
    }
    if (strlen(udp_dat) > (IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN))
    {
        fprintf(stderr, "Maximum UDP data length exceeded. Maximum length is %i\n", IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN);
        exit(EXIT_FAILURE);
    }

    // Interface to send packet through.
    // You need to put your network interface name here.
    strcpy(interface, "eno1");

    // Submit request for a socket descriptor to lookup interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to lookup interface and get MAC address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl() failed to get source MAC address ");
        return (EXIT_FAILURE);
    }
    close(sd);

    // Copy source MAC address.
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

    // Resolve interface index.
    memset(&device, 0, sizeof(device));
    if ((device.sll_ifindex = if_nametoindex(interface)) == 0)
    {
        perror("if_nametoindex() failed to obtain interface index ");
        exit(EXIT_FAILURE);
    }
    printf("\nInterface %s with index %i has MAC address ", interface, device.sll_ifindex);
    for (i = 0; i < 5; i++)
    {
        printf("%02x:", src_mac[i]);
    }
    printf("%02x\n", src_mac[5]);

    // Set destination MAC address: you need to fill these out
    dst_mac[0] = 0xff;
    dst_mac[1] = 0xff;
    dst_mac[2] = 0xff;
    dst_mac[3] = 0xff;
    dst_mac[4] = 0xff;
    dst_mac[5] = 0xff;

    // Source IPv4 address: you need to fill this out
    strcpy(src_ip, "192.168.0.9");

    // Destination URL or IPv4 address: you need to fill this out
    strcpy(target, "www.google.com");

    // Fill out hints for getaddrinfo().
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo() failed for target: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }
    dst = (struct sockaddr_in *)res->ai_addr;
    tmp = &(dst->sin_addr);
    if (inet_ntop(AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL)
    {
        status = errno;
        fprintf(stderr, "inet_ntop() failed for target.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
    device.sll_halen = 6;

    // Show target of traceroute.
    printf("\ntraceroute to %s (%s)\n", target, dst_ip);

    // Submit request for a raw socket descriptors - one to send, one to receive.
    if ((sendsd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed to obtain a send socket descriptor ");
        exit(EXIT_FAILURE);
    }
    if ((recsd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed to obtain a receive socket descriptor ");
        exit(EXIT_FAILURE);
    }

    // Set time limit for receive socket to time-out.
    wait.tv_sec = TIMEOUT; // seconds
    wait.tv_usec = 0;      // microseconds

    // Set receive socket to be non-blocking. We will use select() to monitor the socket for incoming data.
    // First, obtain existing flags from receive socket.
    if ((flags = fcntl(recsd, F_GETFL, 0)) == -1)
    {
        status = errno;
        fprintf(stderr, "ERROR: Failed to obtain flags from receive socket.\n");
        fprintf(stderr, "       errno: %i\n", status);
        exit(EXIT_FAILURE);
    }
    // Set flag to make receive socket non-blocking.
    if (fcntl(recsd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        status = errno;
        fprintf(stderr, "ERROR: Failed to set receive socket to be non-blocking.\n");
        fprintf(stderr, "       errno: %i\n", status);
        exit(EXIT_FAILURE);
    }

    // Set maximum number of tries for a host before incrementing TTL and moving on.
    trylim = 3;

    // Start at TTL = 1;
    node = 1;

    // LOOP: incrementing TTL each cycle, exiting when we get our target IP address.
    iphdr = (struct ip *)(rec_ether_frame + ETH_HDRLEN);
    icmphdr = (struct icmp *)(rec_ether_frame + ETH_HDRLEN + IP4_HDRLEN);
    tcphdr = (struct tcphdr *)(rec_ether_frame + ETH_HDRLEN + IP4_HDRLEN);
    done = 0;
    trycount = 0;
    probes = 0;

    for (;;)
    {

        // Create probe packet.
        memset(snd_ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
        if (packet_type == 1)
        {
            datalen = strlen(tcp_dat);
            memcpy(data, tcp_dat, datalen * sizeof(uint8_t));
            create_tcp_frame(snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, node, data, datalen);
            // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
            frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN + datalen;
        }
        else if (packet_type == 2)
        {
            datalen = strlen(icmp_dat);
            memcpy(data, icmp_dat, datalen * sizeof(uint8_t));
            create_icmp_frame(snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, node, data, datalen);
            // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header)
            frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + datalen;
        }
        else if (packet_type == 3)
        {
            datalen = strlen(udp_dat);
            memcpy(data, udp_dat, datalen * sizeof(uint8_t));
            create_udp_frame(snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, node, data, datalen);
            // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header)
            frame_length = 6 + 6 + 2 + IP4_HDRLEN + UDP_HDRLEN + datalen;
        }

        // SEND

        // Send ethernet frame to socket.
        if ((bytes = sendto(sendsd, snd_ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
        {
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }

        probes++;

        // Start timer.
        (void)gettimeofday(&t1, &tz);

        // Listen for incoming ethernet frame from socket sd.
        // We expect an ICMP ethernet frame of the form:
        //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
        //     + ethernet data (IP header + ICMP header + IP header + TCP/ICMP/UDP header)
        // Keep at it for 'timeout' seconds, or until we get an ICMP reply.

        // RECEIVE LOOP
        for (;;)
        {

            memset(rec_ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
            memset(&from, 0, sizeof(from));
            fromlen = sizeof(from);

            FD_ZERO(&rset);       // Clear set of socket descriptors to be monitored by select().
            FD_SET(recsd, &rset); // Add recsd to set of socket descriptors to be monitored by select(). In this case, the "set" only contains recsd.

            // Wait for data to be available on our receive socket, or until we time-out.
            // After select() has returned, rset will be cleared of all socket descriptors (we actually only added recsd) except for those that are ready for reading.
            if (select(recsd + 1, &rset, NULL, NULL, &wait) < 0)
            {

                status = errno;
                fprintf(stderr, "ERROR: select() failed with errno: %i.\n", status);
                exit(EXIT_FAILURE);
            }

            // If recsd is still in rset, it is ready for reading.
            if (FD_ISSET(recsd, &rset))
            {

                // Read available data from recsd.
                if ((bytes = recvfrom(recsd, rec_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *)&from, &fromlen)) < 0)
                {

                    status = errno;

                    // Deal with error conditions first.
                    if (status == EINTR)
                    {             // EINTR = 4
                        continue; // Something weird happened, but let's keep listening.
                    }
                    else
                    {
                        perror("recvfrom() failed: \n");
                        exit(EXIT_FAILURE);
                    }
                } // End of error handling conditionals.

                // Receive socket timed-out.
            }
            else
            {
                printf("%2i  No reply within %i seconds.\n", node, TIMEOUT);
                trycount++;
                // Reset timer which gets altered by select().
                wait.tv_sec = TIMEOUT; // seconds
                wait.tv_usec = 0;      // microseconds
                break;                 // Break out of Receive loop.
            }

            // Check for an IP ethernet frame. If not, ignore and keep listening.
            if (((rec_ether_frame[12] << 8) + rec_ether_frame[13]) == ETH_P_IP)
            {

                // Did we get an ICMP_TIME_EXCEEDED?
                if ((iphdr->ip_p == IPPROTO_ICMP) && (icmphdr->icmp_type == ICMP_TIME_EXCEEDED))
                {

                    trycount = 0;
                    // Stop timer and calculate how long it took to get a reply.
                    (void)gettimeofday(&t2, &tz);
                    dt = (double)(t2.tv_sec - t1.tv_sec) * 1000.0 + (double)(t2.tv_usec - t1.tv_usec) / 1000.0;

                    // Extract source IP address from received ethernet frame.
                    if (inet_ntop(AF_INET, &(iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL)
                    {
                        status = errno;
                        fprintf(stderr, "inet_ntop() failed for received source address.\nError message: %s", strerror(status));
                        exit(EXIT_FAILURE);
                    }

                    // Report source IP address and time for reply.
                    if (resolve == 0)
                    {
                        printf("%2i  %s  %g ms (%i bytes received)", node, rec_ip, dt, bytes);
                    }
                    else
                    {
                        memset(&sa, 0, sizeof(sa));
                        sa.sin_family = AF_INET;
                        if ((status = inet_pton(AF_INET, rec_ip, &sa.sin_addr)) != 1)
                        {
                            fprintf(stderr, "inet_pton() failed for received source address.\nError message: %s", strerror(status));
                            exit(EXIT_FAILURE);
                        }
                        if ((status = getnameinfo((struct sockaddr *)&sa, sizeof(sa), hostname, sizeof(hostname), NULL, 0, 0)) != 0)
                        {
                            fprintf(stderr, "getnameinfo() failed for received source address.\nError message: %s", strerror(status));
                            exit(EXIT_FAILURE);
                        }
                        printf("%2i  %s (%s)  %g ms (%i bytes received)", node, rec_ip, hostname, dt, bytes);
                    }
                    if (probes < num_probes)
                    {
                        printf(" : ");
                        break; // Break out of Receive loop and probe next node in route.
                    }
                    else
                    {
                        printf("\n");
                        node++;
                        probes = 0;
                        break; // Break out of Receive loop and probe next node in route.
                    }
                } // End of ICMP_TIME_EXCEEDED conditional.

                // Did we reach our destination?
                // TCP SYN-ACK means TCP SYN packet reached destination node.
                // ICMP echo reply means ICMP echo request packet reached destination node.
                // ICMP port unreachable means UDP packet reached destination node.
                if (((iphdr->ip_p == IPPROTO_TCP) && (tcphdr->th_flags == 18)) ||                                // (18 = SYN, ACK)
                    ((iphdr->ip_p == IPPROTO_ICMP) && (icmphdr->icmp_type == 0) && (icmphdr->icmp_code == 0)) || // ECHO REPLY
                    ((iphdr->ip_p == IPPROTO_ICMP) && (icmphdr->icmp_type == 3) && (icmphdr->icmp_code == 3)))
                { // PORT UNREACHABLE
                    // Stop timer and calculate how long in ms it took to get a reply.
                    (void)gettimeofday(&t2, &tz);
                    dt = (double)(t2.tv_sec - t1.tv_sec) * 1000.0 + (double)(t2.tv_usec - t1.tv_usec) / 1000.0;

                    // Extract source IP address from received ethernet frame.
                    if (inet_ntop(AF_INET, &(iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL)
                    {
                        status = errno;
                        fprintf(stderr, "inet_ntop() failed for received source address.\nError message: %s", strerror(status));
                        exit(EXIT_FAILURE);
                    }

                    // Report source IP address and time for reply.
                    printf("%2i  %s  %g ms", node, rec_ip, dt);
                    if (probes < num_probes)
                    {
                        printf(" : ");
                        break; // Break out of Receive loop and probe this node again.
                    }
                    else
                    {
                        printf("\n");
                        done = 1;
                        break; // Break out of Receive loop and finish.
                    }
                } // End of Reached Destination conditional.
            }     // End of Was IP Frame conditional.
        }         // End of Receive loop.

        // Reached destination node.
        if (done == 1)
        {
            printf("Traceroute complete.\n");
            break; // Break out of Send loop.

            // Reached maxhops.
        }
        else if (node > maxhops)
        {
            printf("Reached maximum number of hops. Maximum is set to %i hops.", maxhops);
            break; // Break out of Send loop.
        }

        // We ran out of tries, let's move on to next node unless we reached maxhops limit.
        if (trycount == trylim)
        {
            printf("%2i  Node won't respond after %i probes.\n", node, trylim);
            node++;
            probes = 0;
            trycount = 0;
            continue;
        }

    } // End of Send loop.

    // Close socket descriptors.
    close(sendsd);
    close(recsd);

    // Free allocated memory.
    free(tcp_dat);
    free(icmp_dat);
    free(udp_dat);
    free(data);
    free(src_mac);
    free(dst_mac);
    free(snd_ether_frame);
    free(rec_ether_frame);
    free(interface);
    free(target);
    free(src_ip);
    free(dst_ip);
    free(rec_ip);

    return (EXIT_SUCCESS);
}

// Create a TCP ethernet frame.
int create_tcp_frame(uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                     int ttl, uint8_t *data, int datalen)
{

    int i, status, *ip_flags, *tcp_flags;
    struct ip iphdr;
    struct tcphdr tcphdr;

    // Allocate memory for various arrays.
    ip_flags = allocate_intmem(4);
    tcp_flags = allocate_intmem(8);

    // IPv4 header

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);

    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;

    // Type of service (8 bits)
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + TCP header + data
    iphdr.ip_len = htons(IP4_HDRLEN + TCP_HDRLEN + datalen);

    // ID sequence number (16 bits): unused, since single datagram
    iphdr.ip_id = htons(0);

    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

    // Zero (1 bit)
    ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip_flags[1] = 0;

    // More fragments following flag (1 bit)
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);

    // Time-to-Live (8 bits): default to maximum value
    iphdr.ip_ttl = ttl;

    // Transport layer protocol (8 bits): 6 for TCP
    iphdr.ip_p = IPPROTO_TCP;

    // Source IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for source address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Destination IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for destination address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

    // TCP header

    // Source port number (16 bits)
    tcphdr.th_sport = htons(80);

    // Destination port number (16 bits)
    tcphdr.th_dport = htons(80);

    // Sequence number (32 bits)
    tcphdr.th_seq = htonl(0);

    // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
    tcphdr.th_ack = htonl(0);

    // Reserved (4 bits): should be 0
    tcphdr.th_x2 = 0;

    // Data offset (4 bits): size of TCP header in 32-bit words
    tcphdr.th_off = TCP_HDRLEN / 4;

    // Flags (8 bits)

    // FIN flag (1 bit)
    tcp_flags[0] = 0;

    // SYN flag (1 bit): set to 1
    tcp_flags[1] = 1;

    // RST flag (1 bit)
    tcp_flags[2] = 0;

    // PSH flag (1 bit)
    tcp_flags[3] = 0;

    // ACK flag (1 bit)
    tcp_flags[4] = 0;

    // URG flag (1 bit)
    tcp_flags[5] = 0;

    // ECE flag (1 bit)
    tcp_flags[6] = 0;

    // CWR flag (1 bit)
    tcp_flags[7] = 0;

    tcphdr.th_flags = 0;
    for (i = 0; i < 8; i++)
    {
        tcphdr.th_flags += (tcp_flags[i] << i);
    }

    // Window size (16 bits)
    tcphdr.th_win = htons(65535);

    // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcphdr.th_urp = htons(0);

    // TCP checksum (16 bits)
    tcphdr.th_sum = tcp4_checksum(iphdr, tcphdr, data, datalen);

    // Fill out ethernet frame header.

    // Destination and Source MAC addresses
    memcpy(snd_ether_frame, dst_mac, 6 * sizeof(uint8_t));
    memcpy(snd_ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    // Next is ethernet type code (ETH_P_IP for IPv4).
    // http://www.iana.org/assignments/ethernet-numbers
    snd_ether_frame[12] = ETH_P_IP / 256;
    snd_ether_frame[13] = ETH_P_IP % 256;

    // Next is ethernet frame data (IPv4 header + TCP header).

    // IPv4 header
    memcpy(snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof(uint8_t));

    // TCP header
    memcpy(snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));

    // TCP data
    memcpy(snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN, data, datalen * sizeof(uint8_t));

    // Free allocated memory.
    free(ip_flags);
    free(tcp_flags);

    return (EXIT_SUCCESS);
}

// Create a ICMP ethernet frame.
int create_icmp_frame(uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                      int ttl, uint8_t *data, int datalen)
{

    int status, *ip_flags;
    struct ip iphdr;
    struct icmp icmphdr;

    // Allocate memory for various arrays.
    ip_flags = allocate_intmem(4);

    // IPv4 header

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);

    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;

    // Type of service (8 bits)
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + datalen);

    // ID sequence number (16 bits): unused, since single datagram
    iphdr.ip_id = htons(0);

    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

    // Zero (1 bit)
    ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip_flags[1] = 0;

    // More fragments following flag (1 bit)
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);

    // Time-to-Live (8 bits): default to maximum value
    iphdr.ip_ttl = ttl;

    // Transport layer protocol (8 bits): 1 for ICMP
    iphdr.ip_p = IPPROTO_ICMP;

    // Source IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for source address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Destination IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for destination address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

    // ICMP header

    // Message Type (8 bits): echo request
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): usually pid of sending process - pick a number
    icmphdr.icmp_id = htons(1000);

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = htons(0);

    // ICMP header checksum (16 bits): set to 0 when calculating checksum
    icmphdr.icmp_cksum = 0;

    // Fill out ethernet frame header.

    // Destination and Source MAC addresses
    memcpy(snd_ether_frame, dst_mac, 6 * sizeof(uint8_t));
    memcpy(snd_ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    // Next is ethernet type code (ETH_P_IP for IPv4).
    // http://www.iana.org/assignments/ethernet-numbers
    snd_ether_frame[12] = ETH_P_IP / 256;
    snd_ether_frame[13] = ETH_P_IP % 256;

    // Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

    // IPv4 header
    memcpy(snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof(uint8_t));

    // ICMP header
    memcpy(snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN * sizeof(uint8_t));

    // ICMP data
    memcpy(snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen * sizeof(uint8_t));

    // Calcuate ICMP checksum
    icmphdr.icmp_cksum = checksum((uint16_t *)(snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN), ICMP_HDRLEN + datalen);
    memcpy(snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN * sizeof(uint8_t));

    // Free allocated memory.
    free(ip_flags);

    return (EXIT_SUCCESS);
}

// Create a UDP ethernet frame.
int create_udp_frame(uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                     int ttl, uint8_t *data, int datalen)
{

    int status, *ip_flags;
    struct ip iphdr;
    struct udphdr udphdr;

    // Allocate memory for various arrays.
    ip_flags = allocate_intmem(4);

    // IPv4 header

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);

    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;

    // Type of service (8 bits)
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + UDP header + datalen
    iphdr.ip_len = htons(IP4_HDRLEN + UDP_HDRLEN + datalen);

    // ID sequence number (16 bits): unused, since single datagram
    iphdr.ip_id = htons(0);

    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

    // Zero (1 bit)
    ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip_flags[1] = 0;

    // More fragments following flag (1 bit)
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);

    // Time-to-Live (8 bits): default to maximum value
    iphdr.ip_ttl = ttl;

    // Transport layer protocol (8 bits): 17 for UDP
    iphdr.ip_p = IPPROTO_UDP;

    // Source IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for source address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Destination IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for destination address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

    // UDP header

    // Source port number (16 bits): pick a number
    udphdr.uh_sport = htons(4950);

    // Destination port number (16 bits): pick a number
    udphdr.uh_dport = htons(33435);

    // Length of UDP datagram (16 bits): UDP header + UDP data
    udphdr.uh_ulen = htons(UDP_HDRLEN + datalen);

    // UDP checksum (16 bits)
    udphdr.uh_sum = udp4_checksum(iphdr, udphdr, data, datalen);

    // Fill out ethernet frame header.

    // Destination and Source MAC addresses
    memcpy(snd_ether_frame, dst_mac, 6 * sizeof(uint8_t));
    memcpy(snd_ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    // Next is ethernet type code (ETH_P_IP for IPv4).
    // http://www.iana.org/assignments/ethernet-numbers
    snd_ether_frame[12] = ETH_P_IP / 256;
    snd_ether_frame[13] = ETH_P_IP % 256;

    // Next is ethernet frame data (IPv4 header + UDP header + UDP data).
    // IPv4 header
    memcpy(snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof(uint8_t));

    // UDP header
    memcpy(snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &udphdr, UDP_HDRLEN * sizeof(uint8_t));

    // UDP data
    memcpy(snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN, data, datalen * sizeof(uint8_t));

    // Free allocated memory.
    free(ip_flags);

    return (EXIT_SUCCESS);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum is not guaranteed to preclude collisions.
uint16_t
checksum(uint16_t *addr, int len)
{

    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1)
    {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0)
    {
        sum += *(uint8_t *)addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t
tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen)
{

    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy source IP address into buf (32 bits)
    memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
    ptr += sizeof(iphdr.ip_src.s_addr);
    chksumlen += sizeof(iphdr.ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
    ptr += sizeof(iphdr.ip_dst.s_addr);
    chksumlen += sizeof(iphdr.ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0;
    ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
    ptr += sizeof(iphdr.ip_p);
    chksumlen += sizeof(iphdr.ip_p);

    // Copy TCP length to buf (16 bits)
    svalue = htons(sizeof(tcphdr) + payloadlen);
    memcpy(ptr, &svalue, sizeof(svalue));
    ptr += sizeof(svalue);
    chksumlen += sizeof(svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy(ptr, &tcphdr.th_sport, sizeof(tcphdr.th_sport));
    ptr += sizeof(tcphdr.th_sport);
    chksumlen += sizeof(tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy(ptr, &tcphdr.th_dport, sizeof(tcphdr.th_dport));
    ptr += sizeof(tcphdr.th_dport);
    chksumlen += sizeof(tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy(ptr, &tcphdr.th_seq, sizeof(tcphdr.th_seq));
    ptr += sizeof(tcphdr.th_seq);
    chksumlen += sizeof(tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy(ptr, &tcphdr.th_ack, sizeof(tcphdr.th_ack));
    ptr += sizeof(tcphdr.th_ack);
    chksumlen += sizeof(tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy(ptr, &cvalue, sizeof(cvalue));
    ptr += sizeof(cvalue);
    chksumlen += sizeof(cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy(ptr, &tcphdr.th_flags, sizeof(tcphdr.th_flags));
    ptr += sizeof(tcphdr.th_flags);
    chksumlen += sizeof(tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy(ptr, &tcphdr.th_win, sizeof(tcphdr.th_win));
    ptr += sizeof(tcphdr.th_win);
    chksumlen += sizeof(tcphdr.th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy(ptr, &tcphdr.th_urp, sizeof(tcphdr.th_urp));
    ptr += sizeof(tcphdr.th_urp);
    chksumlen += sizeof(tcphdr.th_urp);

    // Copy payload to buf
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++)
    {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum((uint16_t *)buf, chksumlen);
}

// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t
icmp4_checksum(struct icmp icmphdr, uint8_t *payload, int payloadlen)
{

    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy Message Type to buf (8 bits)
    memcpy(ptr, &icmphdr.icmp_type, sizeof(icmphdr.icmp_type));
    ptr += sizeof(icmphdr.icmp_type);
    chksumlen += sizeof(icmphdr.icmp_type);

    // Copy Message Code to buf (8 bits)
    memcpy(ptr, &icmphdr.icmp_code, sizeof(icmphdr.icmp_code));
    ptr += sizeof(icmphdr.icmp_code);
    chksumlen += sizeof(icmphdr.icmp_code);

    // Copy ICMP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy Identifier to buf (16 bits)
    memcpy(ptr, &icmphdr.icmp_id, sizeof(icmphdr.icmp_id));
    ptr += sizeof(icmphdr.icmp_id);
    chksumlen += sizeof(icmphdr.icmp_id);

    // Copy Sequence Number to buf (16 bits)
    memcpy(ptr, &icmphdr.icmp_seq, sizeof(icmphdr.icmp_seq));
    ptr += sizeof(icmphdr.icmp_seq);
    chksumlen += sizeof(icmphdr.icmp_seq);

    // Copy payload to buf
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++)
    {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum((uint16_t *)buf, chksumlen);
}

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t
udp4_checksum(struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{

    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy source IP address into buf (32 bits)
    memcpy(ptr, &iphdr.ip_src.s_addr, sizeof(iphdr.ip_src.s_addr));
    ptr += sizeof(iphdr.ip_src.s_addr);
    chksumlen += sizeof(iphdr.ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof(iphdr.ip_dst.s_addr));
    ptr += sizeof(iphdr.ip_dst.s_addr);
    chksumlen += sizeof(iphdr.ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0;
    ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy(ptr, &iphdr.ip_p, sizeof(iphdr.ip_p));
    ptr += sizeof(iphdr.ip_p);
    chksumlen += sizeof(iphdr.ip_p);

    // Copy UDP length to buf (16 bits)
    memcpy(ptr, &udphdr.uh_ulen, sizeof(udphdr.uh_ulen));
    ptr += sizeof(udphdr.uh_ulen);
    chksumlen += sizeof(udphdr.uh_ulen);

    // Copy UDP source port to buf (16 bits)
    memcpy(ptr, &udphdr.uh_sport, sizeof(udphdr.uh_sport));
    ptr += sizeof(udphdr.uh_sport);
    chksumlen += sizeof(udphdr.uh_sport);

    // Copy UDP destination port to buf (16 bits)
    memcpy(ptr, &udphdr.uh_dport, sizeof(udphdr.uh_dport));
    ptr += sizeof(udphdr.uh_dport);
    chksumlen += sizeof(udphdr.uh_dport);

    // Copy UDP length again to buf (16 bits)
    memcpy(ptr, &udphdr.uh_ulen, sizeof(udphdr.uh_ulen));
    ptr += sizeof(udphdr.uh_ulen);
    chksumlen += sizeof(udphdr.uh_ulen);

    // Copy UDP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy payload to buf
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++)
    {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum((uint16_t *)buf, chksumlen);
}

// Allocate memory for an array of chars.
char *
allocate_strmem(int len)
{

    void *tmp;

    if (len <= 0)
    {
        fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (char *)malloc(len * sizeof(char));
    if (tmp != NULL)
    {
        memset(tmp, 0, len * sizeof(char));
        return (tmp);
    }
    else
    {
        fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit(EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem(int len)
{

    void *tmp;

    if (len <= 0)
    {
        fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (uint8_t *)malloc(len * sizeof(uint8_t));
    if (tmp != NULL)
    {
        memset(tmp, 0, len * sizeof(uint8_t));
        return (tmp);
    }
    else
    {
        fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit(EXIT_FAILURE);
    }
}

// Allocate memory for an array of ints.
int *allocate_intmem(int len)
{

    void *tmp;

    if (len <= 0)
    {
        fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
        exit(EXIT_FAILURE);
    }

    tmp = (int *)malloc(len * sizeof(int));
    if (tmp != NULL)
    {
        memset(tmp, 0, len * sizeof(int));
        return (tmp);
    }
    else
    {
        fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
        exit(EXIT_FAILURE);
    }
}