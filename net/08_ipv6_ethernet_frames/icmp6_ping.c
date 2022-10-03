

// Send an IPv6 ICMP echo request packet via raw socket at the link layer (ethernet frame),
// and receive echo reply packet (i.e., ping). Includes some ICMP data.
// Need to have destination MAC address.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>           // struct addrinfo
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>      // needed for socket()
#include <netinet/in.h>      // IPPROTO_ICMPV6, INET6_ADDRSTRLEN
#include <netinet/ip.h>      // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>     // struct ip6_hdr
#include <netinet/icmp6.h>   // struct icmp6_hdr and ICMP6_ECHO_REQUEST
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
#define IP6_HDRLEN 40 // IPv6 header length
#define ICMP_HDRLEN 8 // ICMP header length for echo request, excludes data

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t icmp6_checksum(struct ip6_hdr, struct icmp6_hdr, uint8_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);

int main(int argc, char **argv)
{

    int i, status, datalen, frame_length, sendsd, recvsd, bytes, timeout, trycount, trylim, done;
    char *interface, *target, *src_ip, *dst_ip, *rec_ip;
    struct ip6_hdr send_iphdr, *recv_iphdr;
    struct icmp6_hdr send_icmphdr, *recv_icmphdr;
    uint8_t *data, *src_mac, *dst_mac, *send_ether_frame, *recv_ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in6 *ipv6;
    struct sockaddr_ll device;
    struct ifreq ifr;
    struct sockaddr from;
    socklen_t fromlen;
    struct timeval wait, t1, t2;
    struct timezone tz;
    double dt;
    void *tmp;

    // Allocate memory for various arrays.
    src_mac = allocate_ustrmem(6);
    dst_mac = allocate_ustrmem(6);
    data = allocate_ustrmem(IP_MAXPACKET);
    send_ether_frame = allocate_ustrmem(IP_MAXPACKET);
    recv_ether_frame = allocate_ustrmem(IP_MAXPACKET);
    interface = allocate_strmem(40);
    target = allocate_strmem(INET6_ADDRSTRLEN);
    src_ip = allocate_strmem(INET6_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET6_ADDRSTRLEN);
    rec_ip = allocate_strmem(INET6_ADDRSTRLEN);

    // Interface to send packet through.
    strcpy(interface, "eno1");

    // Submit request for a socket descriptor to look up interface.
    // We'll use it to send packets as well, so we leave it open.
    if ((sendsd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sendsd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl() failed to get source MAC address ");
        return (EXIT_FAILURE);
    }

    // Copy source MAC address.
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

    // Report source MAC address to stdout.
    printf("MAC address for interface %s is ", interface);
    for (i = 0; i < 5; i++)
    {
        printf("%02x:", src_mac[i]);
    }
    printf("%02x\n", src_mac[5]);

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset(&device, 0, sizeof(device));
    if ((device.sll_ifindex = if_nametoindex(interface)) == 0)
    {
        perror("if_nametoindex() failed to obtain interface index ");
        exit(EXIT_FAILURE);
    }
    printf("Index for interface %s is %i\n", interface, device.sll_ifindex);

    // Set destination MAC address: you need to fill these out
    dst_mac[0] = 0xff;
    dst_mac[1] = 0xff;
    dst_mac[2] = 0xff;
    dst_mac[3] = 0xff;
    dst_mac[4] = 0xff;
    dst_mac[5] = 0xff;

    // Source IPv6 address: you need to fill this out
    strcpy(src_ip, "2001:db8::214:51ff:fe2f:1556");

    // Destination URL or IPv6 address: you need to fill this out
    strcpy(target, "ipv6.google.com");

    // Fill out hints for getaddrinfo().
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo() failed for target: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }
    ipv6 = (struct sockaddr_in6 *)res->ai_addr;
    tmp = &(ipv6->sin6_addr);
    if (inet_ntop(AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL)
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

    // ICMP data
    datalen = 4;
    data[0] = 'T';
    data[1] = 'e';
    data[2] = 's';
    data[3] = 't';

    // IPv6 header

    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    send_iphdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);

    // Payload length (16 bits): ICMP header + ICMP data
    send_iphdr.ip6_plen = htons(ICMP_HDRLEN + datalen);

    // Next header (8 bits): 58 for ICMP
    send_iphdr.ip6_nxt = IPPROTO_ICMPV6;

    // Hop limit (8 bits): default to maximum value
    send_iphdr.ip6_hops = 255;

    // Source IPv6 address (128 bits)
    if ((status = inet_pton(AF_INET6, src_ip, &(send_iphdr.ip6_src))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for source address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Destination IPv6 address (128 bits)
    if ((status = inet_pton(AF_INET6, dst_ip, &(send_iphdr.ip6_dst))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for destination address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // ICMP header

    // Message Type (8 bits): echo request
    send_icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;

    // Message Code (8 bits): echo request
    send_icmphdr.icmp6_code = 0;

    // Identifier (16 bits): usually pid of sending process - pick a number
    send_icmphdr.icmp6_id = htons(1000);

    // Sequence Number (16 bits): starts at 0
    send_icmphdr.icmp6_seq = htons(0);

    // ICMP header checksum (16 bits): set to 0 when calculating checksum
    send_icmphdr.icmp6_cksum = 0;
    send_icmphdr.icmp6_cksum = icmp6_checksum(send_iphdr, send_icmphdr, data, datalen);

    // Fill out ethernet frame header.

    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
    frame_length = 6 + 6 + 2 + IP6_HDRLEN + ICMP_HDRLEN + datalen;

    // Destination and Source MAC addresses
    memcpy(send_ether_frame, dst_mac, 6 * sizeof(uint8_t));
    memcpy(send_ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    // Next is ethernet type code (ETH_P_IPV6 for IPv6).
    // http://www.iana.org/assignments/ethernet-numbers
    send_ether_frame[12] = ETH_P_IPV6 / 256;
    send_ether_frame[13] = ETH_P_IPV6 % 256;

    // Next is ethernet frame data (IPv6 header + ICMP header + ICMP data).

    // IPv6 header
    memcpy(send_ether_frame + ETH_HDRLEN, &send_iphdr, IP6_HDRLEN * sizeof(uint8_t));

    // ICMP header
    memcpy(send_ether_frame + ETH_HDRLEN + IP6_HDRLEN, &send_icmphdr, ICMP_HDRLEN * sizeof(uint8_t));

    // ICMP data
    memcpy(send_ether_frame + ETH_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN, data, datalen * sizeof(uint8_t));

    // Submit request for a raw socket descriptor to receive packets.
    if ((recvsd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed ");
        exit(EXIT_FAILURE);
    }

    // Set maximum number of tries to ping remote host before giving up.
    trylim = 3;
    trycount = 0;

    // Cast recv_iphdr as pointer to IPv6 header within received ethernet frame.
    recv_iphdr = (struct ip6_hdr *)(recv_ether_frame + ETH_HDRLEN);

    // Cast recv_icmphdr as pointer to ICMP header within received ethernet frame.
    recv_icmphdr = (struct icmp6_hdr *)(recv_ether_frame + ETH_HDRLEN + IP6_HDRLEN);

    done = 0;
    for (;;)
    {

        // SEND

        // Send ethernet frame to socket.
        if ((bytes = sendto(sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
        {
            perror("sendto() failed ");
            exit(EXIT_FAILURE);
        }

        // Start timer.
        (void)gettimeofday(&t1, &tz);

        // Set time for the socket to timeout and give up waiting for a reply.
        timeout = 2;
        wait.tv_sec = timeout;
        wait.tv_usec = 0;
        setsockopt(recvsd, SOL_SOCKET, SO_RCVTIMEO, (char *)&wait, sizeof(struct timeval));

        // Listen for incoming ethernet frame from socket recvsd.
        // We expect an ICMP ethernet frame of the form:
        //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
        //     + ethernet data (IPv6 header + ICMP header)
        // Keep at it for 'timeout' seconds, or until we get an ICMP reply.

        // RECEIVE LOOP
        for (;;)
        {

            memset(recv_ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
            memset(&from, 0, sizeof(from));
            fromlen = sizeof(from);
            if ((bytes = recvfrom(recvsd, recv_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *)&from, &fromlen)) < 0)
            {

                status = errno;

                // Deal with error conditions first.
                if (status == EAGAIN)
                { // EAGAIN = 11
                    printf("No reply within %i seconds.\n", timeout);
                    trycount++;
                    break; // Break out of Receive loop.
                }
                else if (status == EINTR)
                {             // EINTR = 4
                    continue; // Something weird happened, but let's keep listening.
                }
                else
                {
                    perror("recvfrom() failed ");
                    exit(EXIT_FAILURE);
                }
            } // End of error handling conditionals.

            // Check for an IP ethernet frame, carrying ICMP echo reply. If not, ignore and keep listening.
            if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IPV6) &&
                (recv_iphdr->ip6_nxt == IPPROTO_ICMPV6) && (recv_icmphdr->icmp6_type == ICMP6_ECHO_REPLY) && (recv_icmphdr->icmp6_code == 0))
            {

                // Stop timer and calculate how long it took to get a reply.
                (void)gettimeofday(&t2, &tz);
                dt = (double)(t2.tv_sec - t1.tv_sec) * 1000.0 + (double)(t2.tv_usec - t1.tv_usec) / 1000.0;

                // Extract source IP address from received ethernet frame.
                if (inet_ntop(AF_INET6, &(recv_iphdr->ip6_src), rec_ip, INET6_ADDRSTRLEN) == NULL)
                {
                    status = errno;
                    fprintf(stderr, "inet_ntop() failed.\nError message: %s", strerror(status));
                    exit(EXIT_FAILURE);
                }

                // Report source IPv6 address and time for reply.
                printf("%s  %g ms (%i bytes received)\n", rec_ip, dt, bytes);
                done = 1;
                break; // Break out of Receive loop.
            }          // End if IP ethernet frame carrying ICMP_ECHOREPLY
        }              // End of Receive loop.

        // The 'done' flag was set because an echo reply was received; break out of send loop.
        if (done == 1)
        {
            break; // Break out of Send loop.
        }

        // We ran out of tries, so let's give up.
        if (trycount == trylim)
        {
            printf("Recognized no echo replies from remote host after %i tries.\n", trylim);
            break;
        }

    } // End of Send loop.

    // Close socket descriptors.
    close(sendsd);
    close(recvsd);

    // Free allocated memory.
    free(src_mac);
    free(dst_mac);
    free(data);
    free(send_ether_frame);
    free(recv_ether_frame);
    free(interface);
    free(target);
    free(src_ip);
    free(dst_ip);
    free(rec_ip);

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

// Build IPv6 ICMP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
icmp6_checksum(struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen)
{

    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_src.s6_addr, sizeof(iphdr.ip6_src.s6_addr));
    ptr += sizeof(iphdr.ip6_src);
    chksumlen += sizeof(iphdr.ip6_src);

    // Copy destination IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_dst.s6_addr, sizeof(iphdr.ip6_dst.s6_addr));
    ptr += sizeof(iphdr.ip6_dst.s6_addr);
    chksumlen += sizeof(iphdr.ip6_dst.s6_addr);

    // Copy Upper Layer Packet length into buf (32 bits).
    // Should not be greater than 65535 (i.e., 2 bytes).
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = (ICMP_HDRLEN + payloadlen) / 256;
    ptr++;
    *ptr = (ICMP_HDRLEN + payloadlen) % 256;
    ptr++;
    chksumlen += 4;

    // Copy zero field to buf (24 bits)
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy(ptr, &iphdr.ip6_nxt, sizeof(iphdr.ip6_nxt));
    ptr += sizeof(iphdr.ip6_nxt);
    chksumlen += sizeof(iphdr.ip6_nxt);

    // Copy ICMPv6 type to buf (8 bits)
    memcpy(ptr, &icmp6hdr.icmp6_type, sizeof(icmp6hdr.icmp6_type));
    ptr += sizeof(icmp6hdr.icmp6_type);
    chksumlen += sizeof(icmp6hdr.icmp6_type);

    // Copy ICMPv6 code to buf (8 bits)
    memcpy(ptr, &icmp6hdr.icmp6_code, sizeof(icmp6hdr.icmp6_code));
    ptr += sizeof(icmp6hdr.icmp6_code);
    chksumlen += sizeof(icmp6hdr.icmp6_code);

    // Copy ICMPv6 ID to buf (16 bits)
    memcpy(ptr, &icmp6hdr.icmp6_id, sizeof(icmp6hdr.icmp6_id));
    ptr += sizeof(icmp6hdr.icmp6_id);
    chksumlen += sizeof(icmp6hdr.icmp6_id);

    // Copy ICMPv6 sequence number to buff (16 bits)
    memcpy(ptr, &icmp6hdr.icmp6_seq, sizeof(icmp6hdr.icmp6_seq));
    ptr += sizeof(icmp6hdr.icmp6_seq);
    chksumlen += sizeof(icmp6hdr.icmp6_seq);

    // Copy ICMPv6 checksum to buf (16 bits)
    // Zero, since we don't know it yet.
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy ICMPv6 payload to buf
    memcpy(ptr, payload, payloadlen * sizeof(uint8_t));
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++)
    {
        *ptr = 0;
        ptr += 1;
        chksumlen += 1;
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