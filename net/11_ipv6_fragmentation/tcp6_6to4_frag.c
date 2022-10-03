

// Send an IPv6 TCP packet through an IPv4 tunnel (6to4) via raw socket
// at the link layer (ethernet frame) with a large payload requiring fragmentation.
// Includes a TCP header option. Need to have destination MAC address.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>           // struct addrinfo
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>      // needed for socket()
#include <netinet/in.h>      // IPPROTO_IPV6, IPPROTO_TCP, IPPROTO_FRAGMENT, INET_ADDRSTRLEN, INET6_ADDRSTRLEN
#include <netinet/ip.h>      // struct ip and IP_MAXPACKET (which is 65535)
#define __FAVOR_BSD          // Use BSD format of tcp header
#include <netinet/ip6.h>     // struct ip6_hdr
#include <netinet/tcp.h>     // struct tcphdr
#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl. Here, we need SIOCGIFHWADDR.
#include <net/if.h>          // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h> // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP4_HDRLEN 20 // IPv4 header length
#define IP6_HDRLEN 40 // IPv6 header length
#define FRG_HDRLEN 8  // IPv6 fragment header
#define TCP_HDRLEN 20 // TCP header length, excludes options data

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t tcp6_checksum(struct ip6_hdr, struct tcphdr, int, uint8_t *, int, uint8_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

int main(int argc, char **argv)
{

  const int MAX_FRAGS = 1597; // Maximum number of packet fragments (int) (65535 - TCP_HDRLEN) / (IP6_HDRLEN + 1 data byte))
  int i, n, status, frame_length, sd, bytes, opt_len, opt_pad, *frag_flags;
  int *ip4_flags, *tcp_flags, c, nframes, offset[MAX_FRAGS], len[MAX_FRAGS];
  char *interface, *target4, *target6, *source4, *source6, *src_ip, *dst_ip;
  struct ip ip4hdr;
  struct ip6_hdr ip6hdr;
  struct ip6_frag fraghdr;
  struct tcphdr tcphdr;
  int payloadlen, bufferlen;
  uint8_t *options, *payload, *buffer, *src_mac, *dst_mac, *ether_frame;
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
  tcp_flags = allocate_intmem(8);
  src_mac = allocate_ustrmem(6);
  dst_mac = allocate_ustrmem(6);
  ether_frame = allocate_ustrmem(IP_MAXPACKET);
  interface = allocate_strmem(40);
  options = allocate_ustrmem(40);
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

  // Target URL or IPv6 address: you need to fill this out
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
    return (EXIT_FAILURE);
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

  // TCP Options
  // Here we introduce one TCP option.
  opt_len = 0;
  options[0] = 2u;
  opt_len++; // Option kind 2 = maximum segment size
  options[1] = 4u;
  opt_len++; // This option kind is 4 bytes long
  options[2] = 0x1u;
  opt_len++; // Set maximum segment size to 0x100 = 256
  options[3] = 0x0u;
  opt_len++;

  // Pad TCP options to the next 4-byte boundary.
  opt_pad = 0;
  while (((opt_len + opt_pad) % 4) != 0)
  {
    opt_pad++;
  }

  // Get TCP data.
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
  printf("Upper layer protocol header (TCP) length (bytes): %i\n", TCP_HDRLEN);
  printf("TCP options length (bytes): %i\n", opt_len);
  printf("TCP options padding length (bytes): %i\n", opt_pad);
  printf("Payload length (bytes): %i\n", payloadlen);

  // Length of fragmentable portion of packet.
  bufferlen = TCP_HDRLEN + opt_len + opt_pad + payloadlen;
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

  // Payload length (16 bits): fragmentable portion of packet. i.e., TCP header + TCP options + TCP option padding + TCP payload data
  ip6hdr.ip6_plen = htons(TCP_HDRLEN + opt_len + opt_pad + payloadlen);

  // Next header (8 bits) - 6 for TCP
  // This will be changed if we need to fragment but we'll change this to
  // 44 only in ether_frame because otherwise TCP checksum will be wrong.
  ip6hdr.ip6_nxt = IPPROTO_TCP;

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

  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = htons(60);

  // Destination port number (16 bits)
  tcphdr.th_dport = htons(80);

  // Sequence number (32 bits)
  tcphdr.th_seq = htonl(0);

  // Acknowledgement number (32 bits)
  tcphdr.th_ack = htonl(0);

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr.th_off = (TCP_HDRLEN + opt_len + opt_pad) / 4;

  // Flags (8 bits)

  // FIN flag (1 bit)
  tcp_flags[0] = 0;

  // SYN flag (1 bit): Set to 1
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
  tcphdr.th_sum = tcp6_checksum(ip6hdr, tcphdr, opt_len, options, opt_pad, payload, payloadlen);

  // Build fragmentable portion of packet in buffer array.
  memcpy(buffer, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));                                  // TCP header
  memcpy(buffer + TCP_HDRLEN, options, opt_len * sizeof(uint8_t));                        // TCP options
  memcpy(buffer + TCP_HDRLEN + opt_len + opt_pad, payload, payloadlen * sizeof(uint8_t)); // TCP data (note the offset for padding)

  // IPv6 next header (8 bits)
  if (nframes == 1)
  {
    ip6hdr.ip6_nxt = IPPROTO_TCP; // 6 for TCP
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
      fraghdr.ip6f_nxt = IPPROTO_TCP; // Upper layer protocol
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
  } // End loop nframes

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
  free(tcp_flags);
  free(options);
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

// Build IPv6 TCP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
tcp6_checksum(struct ip6_hdr iphdr, struct tcphdr tcphdr, int opt_len, uint8_t *options, int opt_pad, uint8_t *payload, int payloadlen)
{

  uint32_t lvalue;
  char buf[IP_MAXPACKET], cvalue;
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

  // Copy TCP length to buf (32 bits)
  lvalue = htonl(sizeof(tcphdr) + opt_len + opt_pad + payloadlen);
  memcpy(ptr, &lvalue, sizeof(lvalue));
  ptr += sizeof(lvalue);
  chksumlen += sizeof(lvalue);

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
  // NOTE: It is assumed here that the data offset value
  // already accounts for any options padding.
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

  // Copy TCP options into buf.
  memcpy(ptr, options, opt_len * sizeof(uint8_t));
  ptr += opt_len;
  chksumlen += opt_len;

  // Pad options to the next 32-bit boundary.
  ptr += opt_pad;
  chksumlen += opt_pad;

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
