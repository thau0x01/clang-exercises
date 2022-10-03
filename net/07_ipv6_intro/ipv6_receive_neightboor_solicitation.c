

// Receive a neighbor advertisement and extract hop limit,
// destination address and interface index from ancillary
// data, and advertising link-layer address (i.e., MAC)
// from options data.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset()

#include <netinet/icmp6.h> // struct nd_neighbor_solicit/advert, which contains icmp6_hdr and ND_NEIGHBOR_ADVERT
#include <netinet/in.h>    // IPPROTO_IPV6, IPPROTO_ICMPV6, INET6_ADDRSTRLEN
#include <netinet/ip.h>    // IP_MAXPACKET (65535)
#include <arpa/inet.h>     // inet_pton() and inet_ntop()
#include <netdb.h>         // struct addrinfo
#include <sys/ioctl.h>     // macro ioctl is defined
#include <bits/ioctls.h>   // defines values for argument "request" of ioctl. Here, we need SIOCGIFHWADDR
#include <bits/socket.h>   // structs msghdr and cmsghdr
#include <net/if.h>        // struct ifreq

#include <errno.h> // errno, perror()

// Definition of pktinfo6 created from definition of in6_pktinfo in netinet/in.h.
// This should remove "redefinition of in6_pktinfo" errors in some linux variants.
typedef struct _pktinfo6 pktinfo6;
struct _pktinfo6
{
    struct in6_addr ipi6_addr;
    int ipi6_ifindex;
};

// Function prototypes
static void *find_ancillary(struct msghdr *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);

int main(int argc, char **argv)
{

    int i, status, sd, on, ifindex, hoplimit;
    struct nd_neighbor_advert *na;
    uint8_t *inpack;
    int len;
    struct msghdr msghdr;
    struct iovec iov[2];
    uint8_t *opt, *pkt;
    char *interface, *target, *destination;
    struct in6_addr dst;
    int rcv_ifindex;
    struct ifreq ifr;

    // Allocate memory for various arrays.
    inpack = allocate_ustrmem(IP_MAXPACKET);
    target = allocate_strmem(INET6_ADDRSTRLEN);
    interface = allocate_strmem(40);
    destination = allocate_strmem(INET6_ADDRSTRLEN);

    // Interface to receive packet on.
    strcpy(interface, "eno1");

    // Prepare msghdr for recvmsg().
    memset(&msghdr, 0, sizeof(msghdr));
    msghdr.msg_name = NULL;
    msghdr.msg_namelen = 0;
    memset(&iov, 0, sizeof(iov));
    iov[0].iov_base = (uint8_t *)inpack;
    iov[0].iov_len = IP_MAXPACKET;
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;

    msghdr.msg_control = allocate_ustrmem(IP_MAXPACKET);
    msghdr.msg_controllen = IP_MAXPACKET * sizeof(uint8_t);

    // Request a socket descriptor sd.
    if ((sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        perror("Failed to get socket descriptor ");
        exit(EXIT_FAILURE);
    }

    // Set flag so we receive hop limit from recvmsg.
    on = 1;
    if ((status = setsockopt(sd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on))) < 0)
    {
        perror("setsockopt to IPV6_RECVHOPLIMIT failed ");
        exit(EXIT_FAILURE);
    }

    // Set flag so we receive destination address from recvmsg.
    on = 1;
    if ((status = setsockopt(sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on))) < 0)
    {
        perror("setsockopt to IPV6_RECVPKTINFO failed ");
        exit(EXIT_FAILURE);
    }

    // Obtain MAC address of this node.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl() failed to get source MAC address ");
        return (EXIT_FAILURE);
    }

    // Retrieve interface index of this node.
    if ((ifindex = if_nametoindex(interface)) == 0)
    {
        perror("if_nametoindex() failed to obtain interface index ");
        exit(EXIT_FAILURE);
    }
    printf("\nOn this node, index for interface %s is %i\n", interface, ifindex);

    // Bind socket to interface of this node.
    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0)
    {
        perror("SO_BINDTODEVICE failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming message from socket sd.
    // Keep at it until we get a neighbor advertisement.
    na = (struct nd_neighbor_advert *)inpack;
    while (na->nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT)
    {
        if ((len = recvmsg(sd, &msghdr, 0)) < 0)
        {
            perror("recvmsg failed ");
            return (EXIT_FAILURE);
        }
    }

    // Ancillary data
    printf("\nIPv6 header data:\n");
    opt = find_ancillary(&msghdr, IPV6_HOPLIMIT);
    if (opt == NULL)
    {
        fprintf(stderr, "Unknown hop limit\n");
        exit(EXIT_FAILURE);
    }
    hoplimit = *(int *)opt;
    printf("Hop limit: %i\n", hoplimit);

    opt = find_ancillary(&msghdr, IPV6_PKTINFO);
    if (opt == NULL)
    {
        fprintf(stderr, "Unkown destination address\n");
        exit(EXIT_FAILURE);
    }
    memset(&dst, 0, sizeof(dst));
    dst = ((pktinfo6 *)opt)->ipi6_addr;
    if (inet_ntop(AF_INET6, &dst, destination, INET6_ADDRSTRLEN) == NULL)
    {
        status = errno;
        fprintf(stderr, "inet_ntop() failed for received destination address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
    printf("Destination address: %s\n", destination);

    rcv_ifindex = ((pktinfo6 *)opt)->ipi6_ifindex;
    printf("Destination interface index: %i\n", rcv_ifindex);

    // ICMPv6 header and options data
    printf("\nICMPv6 header data:\n");
    printf("Type: %u\n", na->nd_na_hdr.icmp6_type);
    printf("Code: %u\n", na->nd_na_hdr.icmp6_code);
    printf("Checksum: %x\n", ntohs(na->nd_na_hdr.icmp6_cksum));
    printf("Router flag: %u\n", ntohl(na->nd_na_flags_reserved) >> 31);
    printf("Solicited flag: %u\n", (ntohl(na->nd_na_flags_reserved) >> 30) & 1);
    printf("Override flag: %u\n", (ntohl(na->nd_na_flags_reserved) >> 29) & 1);
    printf("Reserved: %i\n", ntohl(na->nd_na_flags_reserved) & 536870911u);
    if (inet_ntop(AF_INET6, &(na->nd_na_target), target, INET6_ADDRSTRLEN) == NULL)
    {
        status = errno;
        fprintf(stderr, "inet_ntop() failed for received target address of neighbor solicitation.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
    printf("Target address of neighbor solicitation: %s\n", target);
    printf("\nOptions:\n");
    pkt = (uint8_t *)inpack;
    printf("Type: %u\n", pkt[sizeof(struct nd_neighbor_advert)]);
    printf("Length: %u (units of 8 octets)\n", pkt[sizeof(struct nd_neighbor_advert) + 1]);
    printf("MAC address: ");
    for (i = 2; i < 7; i++)
    {
        printf("%02x:", pkt[sizeof(struct nd_neighbor_advert) + i]);
    }
    printf("%02x\n", pkt[sizeof(struct nd_neighbor_advert) + 7]);

    close(sd);

    // Free allocated memory.
    free(inpack);
    free(target);
    free(interface);
    free(destination);
    free(msghdr.msg_control);

    return (EXIT_SUCCESS);
}

static void *
find_ancillary(struct msghdr *msg, int cmsg_type)
{

    struct cmsghdr *cmsg = NULL;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg))
    {
        if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == cmsg_type))
        {
            return (CMSG_DATA(cmsg));
        }
    }

    return (NULL);
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