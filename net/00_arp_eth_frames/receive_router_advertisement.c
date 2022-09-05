// Receive an IPv4 router advertisement and extract
// various information stored in the ethernet frame.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset()

#include <netinet/in.h>      // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>      // struct ip and IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>       // inet_ntop()
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>      // needed for socket()
#include <netinet/ip_icmp.h> // ICMP_ROUTERADVERT
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_ALL = 0x0003
#include <net/ethernet.h>

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
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);

int main(int argc, char **argv)
{

    int i, offset, sd, status;
    uint8_t *ether_frame;
    struct ip *iphdr;
    ra_hdr *rahdr;
    char *src_ip, *dst_ip;

    // Allocate memory for various arrays.
    ether_frame = allocate_ustrmem(IP_MAXPACKET);
    src_ip = allocate_strmem(INET_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET_ADDRSTRLEN);

    // Submit request for a raw socket descriptor.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket() failed ");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming ethernet frame from socket sd.
    // We expect a router advertisment ethernet frame of the form:
    //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
    //     + ethernet data (IPv4 header + RA header)
    // Keep at it until we get a router advertisement.
    iphdr = (struct ip *)(ether_frame + 6 + 6 + 2);
    rahdr = (ra_hdr *)(ether_frame + 6 + 6 + 2 + IP4_HDRLEN);
    while (((((ether_frame[12]) << 8) + ether_frame[13]) != ETH_P_IP) || (iphdr->ip_p != IPPROTO_ICMP) ||
           (rahdr->icmp_type != ICMP_ROUTERADVERT))
    {
        if ((status = recv(sd, ether_frame, IP_MAXPACKET, 0)) < 0)
        {
            if (errno == EINTR)
            {
                memset(ether_frame, 0, IP_MAXPACKET * sizeof(uint8_t));
                continue; // Something weird happened, but let's try again.
            }
            else
            {
                perror("recv() failed:");
                exit(EXIT_FAILURE);
            }
        }
    }
    close(sd);

    // Print out contents of received ethernet frame.
    printf("\nEthernet frame header:\n");
    printf("Destination MAC (this node): ");
    for (i = 0; i < 5; i++)
    {
        printf("%02x:", ether_frame[i]);
    }
    printf("%02x\n", ether_frame[5]);
    printf("Source MAC: ");
    for (i = 0; i < 5; i++)
    {
        printf("%02x:", ether_frame[i + 6]);
    }
    printf("%02x\n", ether_frame[11]);
    // Next is ethernet type code (ETH_P_IP for IPv4 packets).
    // http://www.iana.org/assignments/ethernet-numbers
    printf("Ethernet type code (2048 = IPv4): %u\n", ((ether_frame[12]) << 8) + ether_frame[13]);
    printf("\nEthernet data (IPv4 header + Router Advertisement header)\n");
    printf("IPv4 transport layer protocol (1 = ICMP): %u\n", iphdr->ip_p);
    if (inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN) == NULL)
    {
        status = errno;
        fprintf(stderr, "inet_ntop() failed for received source address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
    printf("Source IPv4 address: %s\n", src_ip);
    if (inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN) == NULL)
    {
        status = errno;
        fprintf(stderr, "inet_ntop() failed for received destination address.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
    printf("Destination IPv4 address: %s\n", dst_ip);
    printf("ICMP message type (9 = router advertisement): %u\n", rahdr->icmp_type);
    printf("ICMP message code: %u\n", rahdr->icmp_code);
    printf("Number of IPv4 addresses associated with router: %u\n", rahdr->num_addrs);
    printf("Router address entry size (in units of 32 bit words): %u\n", rahdr->entry_size);
    printf("Lifetime of validity of router advertisement (seconds): %u\n", ntohs(rahdr->lifetime));
    offset = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN; // Start of list of addresses and preference levels within ethernet frame
    for (i = 0; i < rahdr->num_addrs; i++)
    {
        printf("Router %i IPv4 address: %u:%u:%u:%u\n",
               i, ether_frame[offset + (i * rahdr->entry_size * 4) + 0],
               ether_frame[offset + (i * rahdr->entry_size * 4) + 1],
               ether_frame[offset + (i * rahdr->entry_size * 4) + 2],
               ether_frame[offset + (i * rahdr->entry_size * 4) + 3]);
        printf("Router %i preference level: %u\n", i, ((ether_frame[offset + (i * rahdr->entry_size * 4) + 4]) << 24) + ((ether_frame[offset + (i * rahdr->entry_size * 4) + 5]) << 16) + ((ether_frame[offset + (i * rahdr->entry_size * 4) + 6]) << 8) + ether_frame[offset + (i * rahdr->entry_size * 4) + 7]);
        offset += rahdr->entry_size * 4;
    }

    free(ether_frame);
    free(src_ip);
    free(dst_ip);

    return (EXIT_SUCCESS);
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