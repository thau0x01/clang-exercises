

// Send an IPv6 ICMP echo request packet through an IPv4 tunnel (6to4)
// via raw socket at the link layer (ethernet frame).

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netinet/ip.h>      // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/in.h>      // IPPROTO_RAW, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_ICMPV6, INET_ADDRSTRLEN, INET6_ADDRSTRLEN
#include <netinet/ip6.h>     // struct ip6_hdr
#include <netinet/icmp6.h>   // struct icmp6_hdr
#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <netdb.h>           // struct addrinfo
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl. Here, we need SIOCGIFHWADDR
#include <net/if.h>          // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h> // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP4_HDRLEN 20 // IPv4 header length
#define IP6_HDRLEN 40 // IPv6 header length
#define ICMP_HDRLEN 8 // ICMP header length for echo request, excludes data

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t icmp6_checksum(struct ip6_hdr, struct icmp6_hdr, uint8_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

int main(int argc, char **argv)
{

    int i, status, *ip4_flags, datalen, sd, bytes, frame_length;
    struct ip ip4hdr;
    struct ip6_hdr ip6hdr;
    struct icmp6_hdr icmphdr;
    struct addrinfo hints;
    struct addrinfo *res;
    struct sockaddr_in6 *ipv6, src, dst;
    struct sockaddr_ll device;
    struct ifreq ifr;
    uint8_t *ether_frame, *src_mac, *dst_mac, *data, *psdhdr;
    char *interface, *target4, *target6, *source4, *source6, *src_ip, *dst_ip;
    void *tmp;

    // We will add 4 bytes of ICMP data later. Can be anything you choose.
    datalen = 4;

    // Allocate memory for various arrays.
    interface = allocate_strmem(40);
    target4 = allocate_strmem(INET_ADDRSTRLEN);
    target6 = allocate_strmem(INET6_ADDRSTRLEN);
    source4 = allocate_strmem(INET_ADDRSTRLEN);
    source6 = allocate_strmem(INET6_ADDRSTRLEN);
    src_ip = allocate_strmem(INET6_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET6_ADDRSTRLEN);
    src_mac = allocate_ustrmem(6);
    dst_mac = allocate_ustrmem(6);
    ether_frame = allocate_ustrmem(IP_MAXPACKET);
    ip4_flags = allocate_intmem(4);
    data = allocate_ustrmem(IP_MAXPACKET);
    psdhdr = allocate_ustrmem(IP_MAXPACKET);

    // Interface to send packet through.
    strcpy(interface, "eno1");

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its MAC address.
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

    // Report source MAC address to stdout.
    printf("MAC address for interface %s is ", interface);
    for (i = 0; i < 5; i++)
    {
        printf("%02x:", src_mac[i]);
    }
    printf("%02x\n", src_mac[5]);

    // Fill out sockaddr_ll.
    memset(&device, 0, sizeof(device));
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
    device.sll_halen = 6;

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
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

    // Source IPv4 address: you need to fill this out
    strcpy(source4, "192.168.0.240");

    // Source IPv6 address: you need to fill this out
    strcpy(source6, "2001:db8::214:51ff:fe2f:1556");

    // IPv4 target as the 6to4 anycast address (do not change)
    strcpy(target4, "192.88.99.1");

    // Target URL or IPv6 address: you need to fill this out
    strcpy(target6, "ipv6.google.com");

    // Fill out hints for getaddrinfo().
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve source using getaddrinfo().
    if ((status = getaddrinfo(source6, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo() failed for IPv6 source: %s\n", gai_strerror(status));
        return (EXIT_FAILURE);
    }
    memset(&src, 0, sizeof(src));
    memcpy(&src, res->ai_addr, res->ai_addrlen);
    ipv6 = (struct sockaddr_in6 *)res->ai_addr;
    tmp = &(ipv6->sin6_addr);
    memcpy(psdhdr, tmp, INET_ADDRSTRLEN); // Copy to checksum pseudo-header
    if (inet_ntop(AF_INET6, tmp, src_ip, INET6_ADDRSTRLEN) == NULL)
    {
        status = errno;
        fprintf(stderr, "inet_ntop() failed for IPv6 source.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo(target6, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo() failed for IPv6 target: %s\n", gai_strerror(status));
        return (EXIT_FAILURE);
    }
    memset(&dst, 0, sizeof(dst));
    memcpy(&dst, res->ai_addr, res->ai_addrlen);
    ipv6 = (struct sockaddr_in6 *)res->ai_addr;
    tmp = &(ipv6->sin6_addr);
    memcpy(psdhdr + 16, tmp, INET_ADDRSTRLEN); // Copy to checksum pseudo-header
    if (inet_ntop(AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL)
    {
        status = errno;
        fprintf(stderr, "inet_ntop() failed for IPv6 target.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // Copy options data into options buffer.
    // datalen was set to 4 above
    data[0] = 'T';
    data[1] = 'e';
    data[2] = 's';
    data[3] = 't';

    // IPv4 header (Section 3.5 of RFC 4213)

    // IPv4 header

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    ip4hdr.ip_hl = sizeof(struct ip) / sizeof(uint32_t);

    // Internet Protocol version (4 bits): IPv4
    ip4hdr.ip_v = 4;

    // Type of service (8 bits)
    ip4hdr.ip_tos = 0;

    // Total length of datagram (16 bits): IPv4 header + IPv6 header + ICMP header + ICMP data
    ip4hdr.ip_len = htons(IP4_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN + datalen);

    // ID sequence number (16 bits): unused, since single datagram
    ip4hdr.ip_id = htons(0);

    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

    // Zero (1 bit)
    ip4_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip4_flags[1] = 1;

    // More fragments following flag (1 bit)
    ip4_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip4_flags[3] = 0;

    ip4hdr.ip_off = htons((ip4_flags[0] << 15) + (ip4_flags[1] << 14) + (ip4_flags[2] << 13) + ip4_flags[3]);

    // Time-to-Live (8 bits): use maximum value
    ip4hdr.ip_ttl = 255;

    // Transport layer protocol (8 bits): 41 for IPv6 (Section 3.5 of RFC 4213)
    ip4hdr.ip_p = IPPROTO_IPV6;

    // Source IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, source4, &(ip4hdr.ip_src))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for IPv4 source address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Destination IPv4 address (32 bits)
    if ((status = inet_pton(AF_INET, target4, &(ip4hdr.ip_dst))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for IPv4 destination address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // IPv4 header checksum (16 bits) - set to 0 when calculating checksum
    ip4hdr.ip_sum = 0;
    ip4hdr.ip_sum = checksum((uint16_t *)&ip4hdr, IP4_HDRLEN);

    // IPv6 header

    // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    ip6hdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);

    // Payload length (16 bits)
    ip6hdr.ip6_plen = htons(ICMP_HDRLEN + datalen);

    // Next header (8 bits) - 58 for ICMPV6
    ip6hdr.ip6_nxt = IPPROTO_ICMPV6;

    // Hop limit  (8 bits) - use 255 (RFC 4861)
    ip6hdr.ip6_hops = 255;

    // Source IPv6 address (128 bits)
    if ((status = inet_pton(AF_INET6, src_ip, &(ip6hdr.ip6_src))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for IPv6 source address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // Destination IPv6 address (128 bits)
    if ((status = inet_pton(AF_INET6, dst_ip, &(ip6hdr.ip6_dst))) != 1)
    {
        fprintf(stderr, "inet_pton() failed for IPv6 destination address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }

    // ICMP header

    // Message Type (8 bits): echo request
    icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;

    // Message Code (8 bits): echo request
    icmphdr.icmp6_code = 0;

    // Identifier (16 bits): usually pid of sending process - pick a number
    icmphdr.icmp6_id = htons(1000);

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp6_seq = htons(0);

    // ICMP header checksum (16 bits): set to 0 when calculating checksum
    icmphdr.icmp6_cksum = 0;
    icmphdr.icmp6_cksum = icmp6_checksum(ip6hdr, icmphdr, data, datalen);

    // Fill out ethernet frame header.

    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP4 header + IP6 header + ICMP header + ICMP data)
    frame_length = 6 + 6 + 2 + IP4_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN + datalen;

    // Destination and Source MAC addresses
    memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
    memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    // Next is ethernet type code (ETH_P_IP for IPv4).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_IP / 256;
    ether_frame[13] = ETH_P_IP % 256;

    // Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

    // IPv4 header
    memcpy(ether_frame + ETH_HDRLEN, &ip4hdr, IP4_HDRLEN * sizeof(uint8_t));

    // IPv6 header
    memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN, &ip6hdr, IP6_HDRLEN * sizeof(uint8_t));

    // ICMP header
    memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN + IP6_HDRLEN, &icmphdr, ICMP_HDRLEN * sizeof(uint8_t));

    // ICMP data
    memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN, data, datalen * sizeof(uint8_t));

    // Submit request for a raw socket descriptor.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed ");
        exit(EXIT_FAILURE);
    }

    // Send ethernet frame to socket.
    if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
    {
        perror("sendto() failed");
        exit(EXIT_FAILURE);
    }

    // Close socket.
    close(sd);

    // Free allocated memory.
    free(interface);
    free(src_mac);
    free(dst_mac);
    free(ether_frame);
    free(target4);
    free(target6);
    free(source4);
    free(source6);
    free(src_ip);
    free(dst_ip);
    free(ip4_flags);
    free(data);
    free(psdhdr);

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