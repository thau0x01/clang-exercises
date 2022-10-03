

// Send an IPv6 UDP packet through an IPv4 tunnel (6to4) via raw socket
// at the link layer (ethernet frame) with a large payload requiring fragmentation.
// Need to have destination MAC address.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>           // struct addrinfo
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>      // needed for socket()
#include <netinet/in.h>      // IPPROTO_IPV6, IPPROTO_UDP, IPPROTO_FRAGMENT, INET_ADDRSTRLEN, INET6_ADDRSTRLEN
#include <netinet/ip.h>      // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>     // struct ip6_hdr
#include <netinet/udp.h>     // struct udphdr
#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl. Here, we need SIOCGIFHWADDR.
#include <net/if.h>          // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h> // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define IP6_HDRLEN 40  // IPv6 header length
#define UDP_HDRLEN 8   // UDP header length, excludes data
#define FRG_HDRLEN 8   // IPv6 fragment header
#define MAX_FRAGS 3119 // Maximum number of packet fragments

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t udp6_checksum(struct ip6_hdr, struct udphdr, uint8_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

int main(int argc, char **argv)
{

  int i, n, status, frame_length, sd, bytes, *frag_flags;
  int *ip4_flags, c, nframes, offset[MAX_FRAGS], len[MAX_FRAGS];
  char *interface, *target4, *target6, *source4, *source6, *src_ip, *dst_ip;
  struct ip ip4hdr;
  struct ip6_hdr ip6hdr;
  struct ip6_frag fraghdr;
  struct udphdr udphdr;
  int payloadlen, bufferlen;
  uint8_t *payload, *buffer, *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in6 *ipv6;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;
  FILE *fi;

  // Allocate memory for various arrays.
  target4 = allocate_strmem(INET_ADDRSTRLEN);
  target6 = allocate_strmem(INET6_ADDRSTRLEN);
  source4 = allocate_strmem(INET_ADDRSTRLEN);
  source6 = allocate_strmem(INET6_ADDRSTRLEN);
  src_ip = allocate_strmem(INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem(INET6_ADDRSTRLEN);
  ip4_flags = allocate_intmem(4);
  src_mac = allocate_ustrmem(6);
  dst_mac = allocate_ustrmem(6);
  ether_frame = allocate_ustrmem(IP_MAXPACKET);
  interface = allocate_strmem(40);
  frag_flags = allocate_intmem(2);
  payload = allocate_ustrmem(IP_MAXPACKET);

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
  strcpy(source4, "192.168.0.240");

  // Source IPv6 address: you need to fill this out
  strcpy(source6, "2001:db8::214:51ff:fe2f:1556");

  // IPv4 target as the 6to4 anycast address (do not change)
  strcpy(target4, "192.88.99.1");

  // Destination URL or IPv6 address: you need to fill this out
  strcpy(target6, "ipv6.google.com");

  // Fill out hints for getaddrinfo().
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve source using getaddrinfo().
  if ((status = getaddrinfo(source6, NULL, &hints, &res)) != 0)
  {
    fprintf(stderr, "getaddrinfo() failed for IPv6 source: %s\n", gai_strerror(status));
    return (EXIT_FAILURE);
  }
  ipv6 = (struct sockaddr_in6 *)res->ai_addr;
  tmp = &(ipv6->sin6_addr);
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
    exit(EXIT_FAILURE);
  }
  ipv6 = (struct sockaddr_in6 *)res->ai_addr;
  tmp = &(ipv6->sin6_addr);
  if (inet_ntop(AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL)
  {
    status = errno;
    fprintf(stderr, "inet_ntop() failed for IPv6 target.\nError message: %s", strerror(status));
    exit(EXIT_FAILURE);
  }
  freeaddrinfo(res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
  device.sll_halen = 6;

  // Get UDP data.
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
  printf("IPv6 header length (bytes): %i\n", IP6_HDRLEN);
  printf("Upper layer protocol header length (bytes): %i\n", UDP_HDRLEN);
  printf("Payload length (bytes): %i\n", payloadlen);

  // Length of fragmentable portion of packet.
  bufferlen = UDP_HDRLEN + payloadlen;
  printf("Total fragmentable data (bytes): %i\n", bufferlen);

  // Allocate memory for a buffer for fragmentable portion.
  buffer = allocate_ustrmem(bufferlen);

  // Determine how many ethernet frames we'll need.
  // Fragment IPv6 packet with fragmentation extension headers as usual,
  // but use an MTU of 1280 bytes as per Section 3.2.1 of RFC 4213.
  // Then prepend an IPv4 header (with appropriate 6to4 settings) on each fragment later.
  memset(len, 0, MAX_FRAGS * sizeof(int));
  memset(offset, 0, MAX_FRAGS * sizeof(int));
  i = 0;
  c = 0; // Variable c is index to buffer, which contains upper layer protocol header and data.
  while (c < bufferlen)
  {

    // Do we still need to fragment remainder of fragmentable portion?
    if ((bufferlen - c) > (1280 - IP4_HDRLEN - IP6_HDRLEN - FRG_HDRLEN))
    {                                                       // Yes
      len[i] = 1280 - IP4_HDRLEN - IP6_HDRLEN - FRG_HDRLEN; // len[i] is amount of fragmentable part we can include in this frame.
    }
    else
    {                         // No
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

  // IPv4 header (Section 3.5 of RFC 4213)

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  ip4hdr.ip_hl = sizeof(struct ip) / sizeof(uint32_t);

  // Internet Protocol version (4 bits): IPv4
  ip4hdr.ip_v = 4;

  // Type of service (8 bits)
  ip4hdr.ip_tos = 0;

  // Total length of datagram (16 bits)
  // ip4hdr.ip_len is set for each fragment in loop below.

  // ID sequence number (16 bits)
  ip4hdr.ip_id = htons(31415);

  // Flags, and Fragmentation offset (3, 13 bits)

  // Zero (1 bit)
  ip4_flags[0] = 0;

  // Do not fragment flag (1 bit)
  // Must not be set, as per Section 3.2.1 of RFC 4213.
  ip4_flags[1] = 0;

  // More fragments following flag (1 bit): zero, since we fragment at IPv6 level instead.
  ip4_flags[2] = 0u;

  // Fragmentation offset (13 bits)
  ip4_flags[3] = 0;

  // Flags, and Fragmentation offset (3, 13 bits)
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

  // Payload length (16 bits): fragmentable portion of packet. i.e., UDP header + UDP payload data
  ip6hdr.ip6_plen = htons(UDP_HDRLEN + payloadlen);

  // Next header (8 bits): 17 for UDP
  // This will be changed if we need to fragment but we'll change this to
  // 44 only in ether_frame because otherwise ICMP checksum will be wrong.
  ip6hdr.ip6_nxt = IPPROTO_UDP;

  // Hop limit (8 bits): default to maximum value
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

  // UDP header

  // Source port number (16 bits): pick a number
  udphdr.source = htons(4950);

  // Destination port number (16 bits): pick a number
  udphdr.dest = htons(4950);

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr.len = htons(UDP_HDRLEN + payloadlen);

  // UDP checksum (16 bits)
  udphdr.check = udp6_checksum(ip6hdr, udphdr, payload, payloadlen);

  // Build fragmentable portion of packet in buffer array.
  memcpy(buffer, &udphdr, UDP_HDRLEN * sizeof(uint8_t));
  memcpy(buffer + UDP_HDRLEN, payload, payloadlen * sizeof(uint8_t));

  // IPv6 next header (8 bits)
  if (nframes == 1)
  {
    ip6hdr.ip6_nxt = IPPROTO_UDP; // 17 for UDP
  }
  else
  {
    ip6hdr.ip6_nxt = IPPROTO_FRAGMENT; // 44 for Fragmentation extension header
  }

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

    // Next is ethernet frame data (IPv4 header + IPv6 header + [fragmentation extension header] + fragment).

    // Total length of datagram (16 bits): IPv4 header + IPv6 header + [fragmentation extension header] + fragment
    if (nframes == 1)
    {
      ip4hdr.ip_len = htons(IP4_HDRLEN + IP6_HDRLEN + len[i]);
    }
    else
    {
      ip4hdr.ip_len = htons(IP4_HDRLEN + IP6_HDRLEN + FRG_HDRLEN + len[i]);
    }

    // IPv4 header checksum (16 bits)
    ip4hdr.ip_sum = 0;
    ip4hdr.ip_sum = checksum((uint16_t *)&ip4hdr, IP4_HDRLEN);

    // Copy IPv4 header to ethernet frame.
    memcpy(ether_frame + ETH_HDRLEN, &ip4hdr, IP4_HDRLEN * sizeof(uint8_t));

    // Payload length (16 bits): See 4.5 of RFC 2460.
    if (nframes == 1)
    {
      ip6hdr.ip6_plen = htons(len[i]);
    }
    else
    {
      ip6hdr.ip6_plen = htons(FRG_HDRLEN + len[i]);
    }

    // Copy IPv6 header to ethernet frame.
    memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN, &ip6hdr, IP6_HDRLEN * sizeof(uint8_t));

    // Fill out and copy fragmentation extension header to ethernet frame.
    if (nframes > 1)
    {
      fraghdr.ip6f_nxt = IPPROTO_UDP; // Upper layer protocol
      fraghdr.ip6f_reserved = 0;      // Reserved
      frag_flags[1] = 0;              // Reserved
      if (i < (nframes - 1))
      {
        frag_flags[0] = 1; // More fragments to follow
      }
      else
      {
        frag_flags[0] = 0; // This is the last fragment
      }
      fraghdr.ip6f_offlg = htons((offset[i] << 3) + frag_flags[0] + (frag_flags[1] << 1));
      fraghdr.ip6f_ident = htonl(31415);
      memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN + IP6_HDRLEN, &fraghdr, FRG_HDRLEN * sizeof(uint8_t));
    }

    // Copy fragmentable portion of packet to ethernet frame.
    if (nframes == 1)
    {
      memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN + IP6_HDRLEN, buffer, bufferlen * sizeof(uint8_t));
    }
    else
    {
      memcpy(ether_frame + ETH_HDRLEN + IP4_HDRLEN + IP6_HDRLEN + FRG_HDRLEN, buffer + (offset[i] * 8), len[i] * sizeof(uint8_t));
    }

    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IPv4 header + IPv6 header + [fragment header] + fragment)
    if (nframes == 1)
    {
      frame_length = ETH_HDRLEN + IP4_HDRLEN + IP6_HDRLEN + len[i];
    }
    else
    {
      frame_length = ETH_HDRLEN + IP4_HDRLEN + IP6_HDRLEN + FRG_HDRLEN + len[i];
    }

    // Send ethernet frame to socket.
    printf("Sending fragment: %i\n", i);
    if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0)
    {
      perror("sendto() failed");
      exit(EXIT_FAILURE);
    }
  }

  // Close socket descriptor.
  close(sd);

  // Free allocated memory.
  free(target4);
  free(target6);
  free(source4);
  free(source6);
  free(src_mac);
  free(dst_mac);
  free(ether_frame);
  free(interface);
  free(src_ip);
  free(dst_ip);
  free(ip4_flags);
  free(frag_flags);
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

// Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
udp6_checksum(struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{

  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  memset(buf, 0, IP_MAXPACKET * sizeof(uint8_t));

  ptr = &buf[0]; // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy(ptr, &iphdr.ip6_src.s6_addr, sizeof(iphdr.ip6_src.s6_addr));
  ptr += sizeof(iphdr.ip6_src.s6_addr);
  chksumlen += sizeof(iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy(ptr, &iphdr.ip6_dst.s6_addr, sizeof(iphdr.ip6_dst.s6_addr));
  ptr += sizeof(iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof(iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
  ptr += sizeof(udphdr.len);
  chksumlen += sizeof(udphdr.len);

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

  // Copy UDP source port to buf (16 bits)
  memcpy(ptr, &udphdr.source, sizeof(udphdr.source));
  ptr += sizeof(udphdr.source);
  chksumlen += sizeof(udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy(ptr, &udphdr.dest, sizeof(udphdr.dest));
  ptr += sizeof(udphdr.dest);
  chksumlen += sizeof(udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy(ptr, &udphdr.len, sizeof(udphdr.len));
  ptr += sizeof(udphdr.len);
  chksumlen += sizeof(udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0;
  ptr++;
  *ptr = 0;
  ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy(ptr, payload, payloadlen * sizeof(uint8_t));
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
