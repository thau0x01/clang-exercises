

// Send an IPv6 ICMP neighbor advertisement packet.
// Change hoplimit and specify interface using ancillary
// data method.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netinet/icmp6.h> // struct nd_neighbor_advert, which contains icmp6_hdr, ND_NEIGHBOR_ADVERT
#include <netinet/in.h>    // IPPROTO_IPV6, IPPROTO_ICMPV6
#include <netinet/ip.h>    // IP_MAXPACKET (65535)
#include <netdb.h>         // struct addrinfo
#include <sys/ioctl.h>     // macro ioctl is defined
#include <bits/ioctls.h>   // defines values for argument "request" of ioctl. Here, we need SIOCGIFHWADDR
#include <bits/socket.h>   // structs msghdr and cmsghdr
#include <net/if.h>        // struct ifreq

// Definition of pktinfo6 created from definition of in6_pktinfo in netinet/in.h.
// This should remove "redefinition of in6_pktinfo" errors in some linux variants.
typedef struct _pktinfo6 pktinfo6;
struct _pktinfo6
{
    struct in6_addr ipi6_addr;
    int ipi6_ifindex;
};

// Function prototypes
uint16_t checksum(uint16_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);

int main(int argc, char **argv)
{

    int NA_HDRLEN = sizeof(struct nd_neighbor_advert); // Length of NA message header
    int optlen = 8;                                    // Option Type (1 byte) + Length (1 byte) + Length of MAC address (6 bytes)

    int i, sd, status, ifindex, cmsglen, psdhdrlen;
    struct addrinfo hints;
    struct addrinfo *res;
    struct sockaddr_in6 src, dst;
    struct nd_neighbor_advert *na;
    uint8_t *outpack, *options, *psdhdr, hoplimit;
    struct msghdr msghdr;
    struct ifreq ifr;
    struct cmsghdr *cmsghdr1, *cmsghdr2;
    pktinfo6 *pktinfo;
    struct iovec iov[2];
    char *target, *source, *interface;

    // Allocate memory for various arrays.
    interface = allocate_strmem(40);
    target = allocate_strmem(40);
    source = allocate_strmem(40);
    outpack = allocate_ustrmem(IP_MAXPACKET);
    options = allocate_ustrmem(optlen);
    psdhdr = allocate_ustrmem(IP_MAXPACKET);

    // Interface to send packet through.
    strcpy(interface, "eno1");

    // Source (node sending advertisement) IPv6 link-local address: you need to fill this out
    strcpy(source, "fe80::");

    // Destination IPv6 address either:
    // 1) unicast address of node which sent solicitation, or if the
    // solicitation came from the unspecified address (::), use the
    // 2) IPv6 "all nodes" link-local multicast address (ff02::1).
    // You need to fill this out.
    strcpy(target, "ff02::1");

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

    // Request a socket descriptor sd.
    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        perror("Failed to get socket descriptor ");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up advertising node's (i.e., source's) interface name and get its MAC address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl() failed to get MAC address of advertising node ");
        return (EXIT_FAILURE);
    }

    // Copy advertising MAC address into options buffer.
    options[0] = 2;          // Option Type - "target link layer address" (Section 4.6 of RFC 4861)
    options[1] = optlen / 8; // Option Length - units of 8 octets (RFC 4861)
    for (i = 0; i < 6; i++)
    {
        options[i + 2] = (uint8_t)ifr.ifr_addr.sa_data[i];
    }

    // Report advertising node MAC address to stdout.
    printf("Advertising node's MAC address for interface %s is ", interface);
    for (i = 0; i < 5; i++)
    {
        printf("%02x:", options[i + 2]);
    }
    printf("%02x\n", options[5 + 2]);

    // Find interface index from interface name.
    // This will be put in cmsghdr data in order to specify the interface we want to use.
    if ((ifindex = if_nametoindex(interface)) == 0)
    {
        perror("if_nametoindex() failed to obtain interface index ");
        exit(EXIT_FAILURE);
    }
    printf("Advertising node's index for interface %s is %i\n", interface, ifindex);

    // Define first part of buffer outpack to be a neighbor advertisement struct.
    na = (struct nd_neighbor_advert *)outpack;
    memset(na, 0, sizeof(*na));

    // Populate icmp6_hdr portion of neighbor advertisement struct.
    na->nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT; // 136 (RFC 4861)
    na->nd_na_hdr.icmp6_code = 0;                  // zero for neighbor advertisement (RFC 4861)
    na->nd_na_hdr.icmp6_cksum = htons(0);          // zero when calculating checksum
    // Set R/S/O flags as: R=0, S=1, O=1. Set reserved to zero (RFC 4861)
    na->nd_na_flags_reserved = htonl((1 << 30) + (1 << 29));
    na->nd_na_target = src.sin6_addr; // Target address (as type in6_addr)

    // Append options to end of neighbor advertisement struct.
    memcpy(outpack + NA_HDRLEN, options, optlen * sizeof(uint8_t));

    // Need a pseudo-header for checksum calculation. Define length. (RFC 2460)
    // Length = source IP (16 bytes) + destination IP (16 bytes)
    //        + upper layer packet length (4 bytes) + zero (3 bytes)
    //        + next header (1 byte)
    psdhdrlen = 16 + 16 + 4 + 3 + 1 + NA_HDRLEN + optlen;

    // Prepare msghdr for sendmsg().
    memset(&msghdr, 0, sizeof(msghdr));
    msghdr.msg_name = &dst; // Destination IPv6 address as struct sockaddr_in6
    msghdr.msg_namelen = sizeof(dst);
    memset(&iov, 0, sizeof(iov));
    iov[0].iov_base = (uint8_t *)outpack; // Point msghdr to buffer outpack
    iov[0].iov_len = NA_HDRLEN + optlen;
    msghdr.msg_iov = iov;  // scatter/gather array
    msghdr.msg_iovlen = 1; // number of elements in scatter/gather array

    // Tell msghdr we're adding cmsghdr data to change hop limit and specify interface.
    // Allocate some memory for our cmsghdr data.
    cmsglen = CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(*pktinfo));
    msghdr.msg_control = allocate_ustrmem(cmsglen);
    msghdr.msg_controllen = cmsglen;

    // Change hop limit to 255 as required for neighbor advertisement (RFC 4861).
    hoplimit = 255u;
    cmsghdr1 = CMSG_FIRSTHDR(&msghdr);
    cmsghdr1->cmsg_level = IPPROTO_IPV6;
    cmsghdr1->cmsg_type = IPV6_HOPLIMIT; // We want to change hop limit
    cmsghdr1->cmsg_len = CMSG_LEN(sizeof(int));
    *(CMSG_DATA(cmsghdr1)) = hoplimit; // Copy pointer to int hoplimit

    // Specify source interface index for this packet via cmsghdr data.
    cmsghdr2 = CMSG_NXTHDR(&msghdr, cmsghdr1);
    cmsghdr2->cmsg_level = IPPROTO_IPV6;
    cmsghdr2->cmsg_type = IPV6_PKTINFO; // We want to specify interface here
    cmsghdr2->cmsg_len = CMSG_LEN(sizeof(*pktinfo));
    pktinfo = (pktinfo6 *)CMSG_DATA(cmsghdr2);
    pktinfo->ipi6_ifindex = ifindex;

    // Compute ICMPv6 checksum (RFC 2460).
    // psdhdr[0 to 15] = source IPv6 address, set earlier.
    // psdhdr[16 to 31] = destination IPv6 address, set earlier.
    psdhdr[32] = 0;                          // Length should not be greater than 65535 (i.e., 2 bytes)
    psdhdr[33] = 0;                          // Length should not be greater than 65535 (i.e., 2 bytes)
    psdhdr[34] = (NA_HDRLEN + optlen) / 256; // Upper layer packet length
    psdhdr[35] = (NA_HDRLEN + optlen) % 256; // Upper layer packet length
    psdhdr[36] = 0;                          // Must be zero
    psdhdr[37] = 0;                          // Must be zero
    psdhdr[38] = 0;                          // Must be zero
    psdhdr[39] = IPPROTO_ICMPV6;
    memcpy(psdhdr + 40, outpack, (NA_HDRLEN + optlen) * sizeof(uint8_t));
    na->nd_na_hdr.icmp6_cksum = checksum((uint16_t *)psdhdr, psdhdrlen);

    printf("Checksum: %x\n", ntohs(na->nd_na_hdr.icmp6_cksum));

    // Send packet.
    if (sendmsg(sd, &msghdr, 0) < 0)
    {
        perror("sendmsg() failed ");
        exit(EXIT_FAILURE);
    }
    close(sd);

    // Free allocated memory.
    free(interface);
    free(target);
    free(source);
    free(outpack);
    free(options);
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