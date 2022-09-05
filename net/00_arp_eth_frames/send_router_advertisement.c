// Send an IPv4 router advertisement packet via raw socket.
// Stack fills out layer 2 (data link) information (MAC addresses) for us.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>           // struct addrinfo
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>      // needed for socket()
#include <netinet/in.h>      // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP
#include <netinet/ip.h>      // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h> // ICMP_ROUTERADVERT
#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl.
#include <net/if.h>          // struct ifreq

#include <errno.h> // errno, perror()

// Define a struct for an IPv4 ICMP router advertisement header
typedef struct _ra_hdr ra_hdr;
struct _ra_hdr
{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_cksum;
    uint8_t num_addrs;
    uint8_t entry_size;
    uint16_t lifetime;
    uint8_t addrs[2040];
};

// Define some constants.
#define IP4_HDRLEN 20 // IPv4 header length
#define ICMP_HDRLEN 8 // IPv4 ICMP header length excluding data

// Function prototypes
uint16_t checksum(uint16_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

int main(int argc, char **argv)
{

    int status, sd, *ip_flags;
    const int on = 1;
    char *interface, *target, *src_ip, *dst_ip;
    struct ip iphdr;
    ra_hdr rahdr;
    uint8_t *packet;
    struct addrinfo hints, *res;
    struct sockaddr_in *ipv4, src, sin;
    struct ifreq ifr;
    void *tmp;

    // Allocate memory for various arrays.
    packet = allocate_ustrmem(IP_MAXPACKET);
    interface = allocate_strmem(40);
    target = allocate_strmem(40);
    src_ip = allocate_strmem(INET_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET_ADDRSTRLEN);
    ip_flags = allocate_intmem(4);

    // Interface to send packet through.
    strcpy(interface, "eno1");

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket() failed to get socket descriptor for using ioctl() ");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface index which we will use to
    // bind socket descriptor sd to specified interface with setsockopt() since
    // none of the other arguments of sendto() specify which interface to use.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl() failed to find interface ");
        return (EXIT_FAILURE);
    }
    close(sd);
    printf("Index for interface %s is %i\n", interface, ifr.ifr_ifindex);

    // Source IPv4 address (the advertising router): you need to fill this out
    // Here we used the default Cisco gateway address.
    strcpy(src_ip, "192.168.1.1");

    // Destination IPv4 address ("all devices" multicast address)
    strcpy(target, "224.0.0.1");

    // Fill out hints for getaddrinfo().
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Put source IP into sockaddr_in struct using getaddrinfo().
    if ((status = getaddrinfo(src_ip, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo() failed for source address: %s\n", gai_strerror(status));
        exit(EXIT_FAILURE);
    }
    memset(&src, 0, sizeof(src));
    memcpy(&src, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

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

    // IPv4 header

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);

    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;

    // Type of service (8 bits)
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + ICMP header + data
    // See ICMP header below.

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

    // Time-to-Live (8 bits): 1 if destination is IP multicast, or >= 1 otherwise (RFC 1256)
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

    // ICMP header

    // Message Type (8 bits): router advertisement
    rahdr.icmp_type = ICMP_ROUTERADVERT;

    // Message Code (8 bits): see RFC 1256
    rahdr.icmp_code = 0;

    // ICMP header checksum (16 bits): set to 0 when calculating checksum
    rahdr.icmp_cksum = 0;

    // Number of IP addresses associated with this router that are included in this advertisement (8 bits)
    rahdr.num_addrs = 1;

    // Total length of datagram (16 bits): IP header + ICMP header (8 bytes * number of addresses)
    // Calculate IPv4 header checksum.
    iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + (rahdr.num_addrs * 8));
    iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

    // Address entry size (8 bits): in units of 32 bit words
    // Each entry is 32 bits for address + 32 bits for address preference
    rahdr.entry_size = 2;

    // Lifetime of validity of this advertisement in seconds (16 bits): typical value
    rahdr.lifetime = htons(1800);

    // Router address entry 1 (32 bits): used default Cisco value of 192.168.1.1 as example
    memcpy(&rahdr.addrs, &src.sin_addr, sizeof(uint32_t));

    // Router address preference 1 (32 bits): choose a number
    // Higher means more preference.
    rahdr.addrs[4] = 0x00;
    rahdr.addrs[5] = 0x00;
    rahdr.addrs[6] = 0x00;
    rahdr.addrs[7] = 0xff;

    // Prepare packet.

    // First part is an IPv4 header.
    memcpy(packet, &iphdr, IP4_HDRLEN * sizeof(uint8_t));

    // Next part of packet is upper layer protocol header.
    memcpy((packet + IP4_HDRLEN), &rahdr, (ICMP_HDRLEN + (rahdr.num_addrs * 8)) * sizeof(uint8_t));

    // Calculate ICMP header checksum
    rahdr.icmp_cksum = checksum((uint16_t *)(packet + IP4_HDRLEN), ICMP_HDRLEN + (rahdr.num_addrs * 8));
    memcpy((packet + IP4_HDRLEN), &rahdr, (ICMP_HDRLEN + (rahdr.num_addrs * 8)) * sizeof(uint8_t));

    // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
    // For that, we need to specify a destination for the kernel in order for it
    // to decide where to send the raw datagram. We fill in a struct in_addr with
    // the desired destination IP address, and pass this structure to the sendto() function.
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

    // Submit request for a raw socket descriptor.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("socket() failed ");
        exit(EXIT_FAILURE);
    }

    // Set flag so socket expects us to provide IPv4 header.
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt() failed to set IP_HDRINCL ");
        exit(EXIT_FAILURE);
    }

    // Bind socket to interface index.
    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
    {
        perror("setsockopt() failed to bind to interface ");
        exit(EXIT_FAILURE);
    }

    // Send packet.
    if (sendto(sd, packet, IP4_HDRLEN + ICMP_HDRLEN + (rahdr.num_addrs * 8), 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)
    {
        perror("sendto() failed ");
        exit(EXIT_FAILURE);
    }

    // Close socket descriptor.
    close(sd);

    // Free allocated memory.
    free(packet);
    free(interface);
    free(target);
    free(src_ip);
    free(dst_ip);
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