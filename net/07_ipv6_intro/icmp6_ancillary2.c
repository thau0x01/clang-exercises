

// Send an IPv6 ICMP echo request packet.
// Changes hoplimit and specifies interface using ancillary data method.
// Includes ICMP data.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <sys/socket.h>    // struct msghdr
#include <netinet/in.h>    // IPPROTO_IPV6, IPPROTO_ICMPV6
#include <netinet/ip.h>    // IP_MAXPACKET (which is 65535)
#include <netinet/icmp6.h> // struct icmp6_hdr, ICMP6_ECHO_REQUEST
#include <netdb.h>         // struct addrinfo
#include <sys/ioctl.h>     // macro ioctl is defined
#include <bits/ioctls.h>   // defines values for argument "request" of ioctl.
#include <net/if.h>        // struct ifreq

#include <errno.h> // errno, perror()

// Taken from <linux/ipv6.h>, also in <netinet/in.h>
struct in6_pktinfo
{
    struct in6_addr ipi6_addr;
    int ipi6_ifindex;
};

// Define some constants.
#define IP6_HDRLEN 40 // IPv6 header length
#define ICMP_HDRLEN 8 // ICMP header length for echo request, excludes data

// Function prototypes
uint16_t checksum(uint16_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);

int main(int argc, char **argv)
{

    int status, datalen, sd, cmsglen, hoplimit, psdhdrlen;
    char *interface, *target, *source;
    struct icmp6_hdr *icmphdr;
    uint8_t *data, *outpack, *psdhdr;
    struct addrinfo hints, *res;
    struct sockaddr_in6 src, dst;
    socklen_t srclen;
    struct ifreq ifr;
    struct msghdr msghdr;
    struct cmsghdr *cmsghdr1, *cmsghdr2;
    struct in6_pktinfo *pktinfo;
    struct iovec iov[2];

    // Allocate memory for various arrays.
    source = allocate_strmem(40);
    target = allocate_strmem(40);
    interface = allocate_strmem(40);
    data = allocate_ustrmem(IP_MAXPACKET);
    outpack = allocate_ustrmem(IP_MAXPACKET);
    psdhdr = allocate_ustrmem(IP_MAXPACKET);

    // Interface to send packet through.
    strcpy(interface, "eno1");

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6)) < 0)
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

    // Source IPv6 address: you need to fill this out
    strcpy(source, "2001:db8::214:51ff:fe2f:1556");

    // Destination URL or IPv6 address: you need to fill this out
    strcpy(target, "ipv6.google.com");

    // Fill out hints for getaddrinfo().
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve source using getaddrinfo().
    if ((status = getaddrinfo(source, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo() failed for source: %s\n", gai_strerror(status));
        return (EXIT_FAILURE);
    }
    memset(&src, 0, sizeof(src));
    memcpy(&src, res->ai_addr, res->ai_addrlen);
    srclen = res->ai_addrlen;
    memcpy(psdhdr, src.sin6_addr.s6_addr, 16 * sizeof(uint8_t)); // Copy to checksum pseudo-header
    freeaddrinfo(res);

    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo() failed for target: %s\n", gai_strerror(status));
        return (EXIT_FAILURE);
    }
    memset(&dst, 0, sizeof(dst));
    memcpy(&dst, res->ai_addr, res->ai_addrlen);
    memcpy(psdhdr + 16, dst.sin6_addr.s6_addr, 16 * sizeof(uint8_t)); // Copy to checksum pseudo-header
    freeaddrinfo(res);

    // Define first part of buffer outpack to be an ICMPV6 struct.
    icmphdr = (struct icmp6_hdr *)outpack;
    memset(icmphdr, 0, ICMP_HDRLEN * sizeof(uint8_t));

    // Populate icmphdr portion of buffer outpack.
    icmphdr->icmp6_type = ICMP6_ECHO_REQUEST;
    icmphdr->icmp6_code = 0;
    icmphdr->icmp6_cksum = 0;
    icmphdr->icmp6_id = htons(5);
    icmphdr->icmp6_seq = htons(300);

    // ICMP data
    datalen = 4;
    data[0] = 'T';
    data[1] = 'e';
    data[2] = 's';
    data[3] = 't';

    // Append ICMP data.
    memcpy(outpack + ICMP_HDRLEN, data, datalen * sizeof(uint8_t));

    // Need a pseudo-header for checksum calculation. Define length. (RFC 2460)
    // Length = source IP (16 bytes) + destination IP (16 bytes)
    //        + upper layer packet length (4 bytes) + zero (3 bytes)
    //        + next header (1 byte)
    psdhdrlen = 16 + 16 + 4 + 3 + 1 + ICMP_HDRLEN + datalen;

    // Compose the msghdr structure.
    memset(&msghdr, 0, sizeof(msghdr));
    msghdr.msg_name = &dst;           // pointer to socket address structure
    msghdr.msg_namelen = sizeof(dst); // size of socket address structure

    memset(&iov, 0, sizeof(iov));
    iov[0].iov_base = (uint8_t *)outpack;
    iov[0].iov_len = ICMP_HDRLEN + datalen;
    msghdr.msg_iov = iov;  // scatter/gather array
    msghdr.msg_iovlen = 1; // number of elements in scatter/gather array

    // Initialize msghdr and control data to total length of the two messages to be sent.
    // Allocate some memory for our cmsghdr data.
    cmsglen = CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct in6_pktinfo));
    msghdr.msg_control = allocate_ustrmem(cmsglen);
    msghdr.msg_controllen = cmsglen;

    // Change hop limit to 255 via cmsghdr data.
    hoplimit = 255;
    cmsghdr1 = CMSG_FIRSTHDR(&msghdr);
    cmsghdr1->cmsg_level = IPPROTO_IPV6;
    cmsghdr1->cmsg_type = IPV6_HOPLIMIT; // We want to change hop limit
    cmsghdr1->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsghdr1)) = hoplimit;

    // Specify source interface index for this packet via cmsghdr data.
    cmsghdr2 = CMSG_NXTHDR(&msghdr, cmsghdr1);
    cmsghdr2->cmsg_level = IPPROTO_IPV6;
    cmsghdr2->cmsg_type = IPV6_PKTINFO; // We want to specify interface here
    cmsghdr2->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsghdr2);
    pktinfo->ipi6_ifindex = ifr.ifr_ifindex;

    // Compute ICMPv6 checksum (RFC 2460).
    // psdhdr[0 to 15] = source IPv6 address, set earlier.
    // psdhdr[16 to 31] = destination IPv6 address, set earlier.
    psdhdr[32] = 0;                             // Length should not be greater than 65535 (i.e., 2 bytes)
    psdhdr[33] = 0;                             // Length should not be greater than 65535 (i.e., 2 bytes)
    psdhdr[34] = (ICMP_HDRLEN + datalen) / 256; // Upper layer packet length
    psdhdr[35] = (ICMP_HDRLEN + datalen) % 256; // Upper layer packet length
    psdhdr[36] = 0;                             // Must be zero
    psdhdr[37] = 0;                             // Must be zero
    psdhdr[38] = 0;                             // Must be zero
    psdhdr[39] = IPPROTO_ICMPV6;
    memcpy(psdhdr + 40, outpack, (ICMP_HDRLEN + datalen) * sizeof(uint8_t));
    icmphdr->icmp6_cksum = checksum((uint16_t *)psdhdr, psdhdrlen);

    printf("Checksum: %x\n", ntohs(icmphdr->icmp6_cksum));

    // Request a socket descriptor sd.
    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        fprintf(stderr, "Failed to get socket descriptor.\n");
        exit(EXIT_FAILURE);
    }

    // Bind the socket descriptor to the source address.
    if (bind(sd, (struct sockaddr *)&src, srclen) != 0)
    {
        fprintf(stderr, "Failed to bind the socket descriptor to the source address.\n");
        exit(EXIT_FAILURE);
    }

    // Send packet.
    if (sendmsg(sd, &msghdr, 0) < 0)
    {
        perror("sendmsg() failed ");
        exit(EXIT_FAILURE);
    }
    close(sd);

    // Free allocated memory.
    free(source);
    free(target);
    free(interface);
    free(data);
    free(outpack);
    free(psdhdr);
    free(msghdr.msg_control);

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