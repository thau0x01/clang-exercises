

// Send an IPv4 ICMP packet via raw socket at the link layer (ethernet frame)
// with a large payload requiring fragmentation.
// Need to have destination MAC address.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>           // struct addrinfo
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>      // needed for socket()
#include <netinet/in.h>      // IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>      // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h> // struct icmp, ICMP_ECHO
#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl.
#include <net/if.h>          // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h> // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data
#define MAX_FRAGS 3120 // Maximum number of packet fragments (int) (65535 - ICMP_HDRLEN) / (IP4_HDRLEN + 1 data byte))

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t icmp4_checksum(struct icmp, uint8_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

int main(int argc, char **argv)
{

    int i, n, status, frame_length, sd, bytes;
    int *ip_flags, mtu, c, nframes, offset[MAX_FRAGS], len[MAX_FRAGS];
    char *interface, *target, *src_ip, *dst_ip;
    struct ip iphdr;
    struct icmp icmphdr;
    int payloadlen, bufferlen;
    uint8_t *payload, *buffer, *src_mac, *dst_mac, *ether_frame;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;
    void *tmp;
    FILE *fi;

    // Allocate memory for various arrays.
    src_mac = allocate_ustrmem(6);
    dst_mac = allocate_ustrmem(6);
    payload = allocate_ustrmem(IP_MAXPACKET);
    ether_frame = allocate_ustrmem(IP_MAXPACKET);
    interface = allocate_strmem(40);
    target = allocate_strmem(40);
    src_ip = allocate_strmem(INET_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET_ADDRSTRLEN);
    ip_flags = allocate_intmem(4);

    // Interface to send packet through.
    strcpy(interface, "eno1");

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to get interface maximum transmission unit (MTU).
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, interface);
    if (ioctl(sd, SIOCGIFMTU, &ifr) < 0)
    {
        perror("ioctl() failed to get MTU ");
        return (EXIT_FAILURE);
    }
    mtu = ifr.ifr_mtu;
    printf("Current MTU of interface %s is: %i\n", interface, mtu);

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

    // Source IPv4 address: you need to fill this out
    strcpy(src_ip, "192.168.0.240");

    // Destination URL or IPv4 address: you need to fill this out
    strcpy(target, "www.google.com");

    // Fill out hints for getaddrinfo().
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo() failed for target: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }
    ipv4 = (struct sockaddr_in *)res->ai_addr;
    tmp = &(ipv4->sin_addr);
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

    // Get ICMP data.
    i = 0;
    fi = fopen("data", "r");
    if (fi == NULL)
    {
        printf("Can't open file 'data'.\n");
        exit(EXIT_FAILURE);
    }
    while ((n = fgetc(fi)) != EOF)
    {
        payload[i] = n;
        i++;
    }
    fclose(fi);
    payloadlen = i;
    printf("Upper layer protocol header length (bytes): %i\n", ICMP_HDRLEN);
    printf("Payload length (bytes): %i\n", payloadlen);

    // Length of fragmentable portion of packet.
    bufferlen = ICMP_HDRLEN + payloadlen;
    printf("Total fragmentable data (bytes): %i\n", bufferlen);

    // Allocate memory for a buffer for fragmentable portion.
    buffer = allocate_ustrmem(bufferlen);

    // Determine how many ethernet frames we'll need.
    memset(len, 0, MAX_FRAGS * sizeof(int));
    memset(offset, 0, MAX_FRAGS * sizeof(int));
    i = 0;
    c = 0; // Variable c is index to buffer, which contains upper layer protocol header and data.
    while (c < bufferlen)
    {

        // Do we still need to fragment remainder of fragmentable portion?
        if ((bufferlen - c) > (mtu - IP4_HDRLEN))
        {                              // Yes
            len[i] = mtu - IP4_HDRLEN; // len[i] is amount of fragmentable part we can include in this frame.
        }
        else
        {                           // No
            len[i] = bufferlen - c; // len[i] is amount of fragmentable part we can include in this frame.
        }
        c += len[i];

        // If not last fragment, make sure we have an even number of 8-byte blocks.
        // Reduce length as necessary.
        if (c < (bufferlen - 1))
        {
            while ((len[i] % 8) > 0)
            {
                len[i]--;
                c--;
            }
        }
        printf("Frag: %i,  Data (bytes): %i,  Data Offset (8-byte blocks): %i\n", i, len[i], offset[i]);
        i++;
        offset[i] = (len[i - 1] / 8) + offset[i - 1];
    }
    nframes = i;
    printf("Total number of frames to send: %i\n", nframes);

    // IPv4 header

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);

    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;

    // Type of service (8 bits)
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits)
    // iphdr.ip_len is set for each fragment in loop below.

    // ID sequence number (16 bits)
    iphdr.ip_id = htons(31415);

    // Flags, and Fragmentation offset (3, 13 bits)

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
    iphdr.ip_ttl = 255;

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

    // ICMP header checksum (16 bits)
    icmphdr.icmp_cksum = icmp4_checksum(icmphdr, payload, payloadlen);

    // Build fragmentable portion of packet in buffer array.
    // ICMP header
    memcpy(buffer, &icmphdr, ICMP_HDRLEN * sizeof(uint8_t));
    // ICMP data
    memcpy(buffer + ICMP_HDRLEN, payload, payloadlen * sizeof(uint8_t));

    // Submit request for a raw socket descriptor.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed ");
        exit(EXIT_FAILURE);
    }

    // Loop through fragments.
    for (i = 0; i < nframes; i++)
    {

        // Set ethernet frame contents to zero initially.
        memset(ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));

        // Fill out ethernet frame header.

        // Copy destination and source MAC addresses to ethernet frame.
        memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
        memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

        // Next is ethernet type code (ETH_P_IP for IPv4).
        // http://www.iana.org/assignments/ethernet-numbers
        ether_frame[12] = ETH_P_IP / 256;
        ether_frame[13] = ETH_P_IP % 256;

        // Next is ethernet frame data (IPv4 header + fragment).

        // Total length of datagram (16 bits): IP header + fragment
        iphdr.ip_len = htons(IP4_HDRLEN + len[i]);

        // More fragments following flag (1 bit)
        if ((nframes > 1) && (i < (nframes - 1)))
        {
            ip_flags[2] = 1u;
        }
        else
        {
            ip_flags[2] = 0u;
        }

        // Fragmentation offset (13 bits)
        ip_flags[3] = offset[i];

        // Flags, and Fragmentation offset (3, 13 bits)
        iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[3]);

        // IPv4 header checksum (16 bits)
        iphdr.ip_sum = 0;
        iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

        // Copy IPv4 header to ethernet frame.
        memcpy(ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof(uint8_t));

        // Copy fragmentable portion of packet to ethernet frame.
        memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN, buffer + (offset[i] * 8), len[i] * sizeof(uint8_t));

        // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + fragment)
        frame_length = ETH_HDRLEN + IP4_HDRLEN + len[i];

        // Send ethernet frame to socket.
        printf("Sending fragment: %i\n", i);
        if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
        {
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }
    } // End loop nframes

    // Close socket descriptor.
    close(sd);

    // Free allocated memory.
    free(src_mac);
    free(dst_mac);
    free(ether_frame);
    free(interface);
    free(target);
    free(src_ip);
    free(dst_ip);
    free(ip_flags);
    free(payload);
    free(buffer);

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

// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t
icmp4_checksum(struct icmp icmphdr, uint8_t *payload, int payloadlen)
{

    char buf[IP_MAXPACKET];
    char *ptr;
    int i, chksumlen = 0;

    memset(buf, 0, IP_MAXPACKET * sizeof(uint8_t));

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
    i = 0;
    while (((payloadlen + i) % 2) != 0)
    {
        i++;
        chksumlen++;
        ptr++;
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