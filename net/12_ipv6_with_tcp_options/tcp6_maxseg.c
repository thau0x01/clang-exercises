

// Send an IPv6 TCP packet via raw socket at the link layer (ethernet frame).
// Need to have destination MAC address.
// Values set for SYN packet with TCP options data which sets maximum
// segment size.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // close()
#include <string.h> // strcpy, memset(), and memcpy()

#include <netdb.h>           // struct addrinfo
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>      // needed for socket()
#include <netinet/in.h>      // IPPROTO_TCP, INET6_ADDRSTRLEN
#include <netinet/ip.h>      // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>     // struct ip6_hdr
#define __FAVOR_BSD          // Use BSD format of tcp header
#include <netinet/tcp.h>     // struct tcphdr
#include <arpa/inet.h>       // inet_pton() and inet_ntop()
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl.
#include <net/if.h>          // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h> // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14 // Ethernet header length
#define IP6_HDRLEN 40 // IPv6 header length
#define TCP_HDRLEN 20 // TCP header length, excludes options data

// Function prototypes
uint16_t checksum(uint16_t *, int);
uint16_t tcp6_checksum(struct ip6_hdr, struct tcphdr, uint8_t *, int);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);

int main(int argc, char **argv)
{

  int i, status, frame_length, sd, bytes, *tcp_flags, opt_len;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip6_hdr iphdr;
  struct tcphdr tcphdr;
  uint8_t *src_mac, *dst_mac, *ether_frame;
  uint8_t *options;
  struct addrinfo hints, *res;
  struct sockaddr_in6 *ipv6;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem(6);
  dst_mac = allocate_ustrmem(6);
  ether_frame = allocate_ustrmem(IP_MAXPACKET);
  interface = allocate_strmem(40);
  target = allocate_strmem(INET6_ADDRSTRLEN);
  src_ip = allocate_strmem(INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem(INET6_ADDRSTRLEN);
  tcp_flags = allocate_intmem(8);
  options = allocate_ustrmem(40);

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

  // Source IPv6 address: you need to fill this out
  strcpy(src_ip, "2001:db8::214:51ff:fe2f:1556");

  // Destination URL or IPv6 address: you need to fill this out
  strcpy(target, "ipv6.google.com");

  // Fill out hints for getaddrinfo().
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_RAW;
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

  // TCP Options
  opt_len = 0;
  options[0] = 2u;
  opt_len++; // Option kind 2 = maximum segment size
  options[1] = 4u;
  opt_len++; // This option kind is 4 bytes long
  options[2] = 0x1u;
  opt_len++; // Set maximum segment size to 0x100 = 256
  options[3] = 0x0u;
  opt_len++;

  // Pad to the next 4-byte boundary.
  while ((opt_len % 4) != 0)
  {
    options[opt_len] = 0;
    opt_len++;
  }
  printf("Padded option length (bytes): %i\n", opt_len);

  // IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr.ip6_flow = htonl((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits): TCP header + TCP options
  iphdr.ip6_plen = htons(TCP_HDRLEN + opt_len);

  // Next header (8 bits): 6 for TCP
  iphdr.ip6_nxt = IPPROTO_TCP;

  // Hop limit (8 bits): default to maximum value
  iphdr.ip6_hops = 255;

  // Source IPv6 address (128 bits)
  if ((status = inet_pton(AF_INET6, src_ip, &(iphdr.ip6_src))) != 1)
  {
    fprintf(stderr, "inet_pton() failed for source address.\nError message: %s", strerror(status));
    exit(EXIT_FAILURE);
  }

  // Destination IPv6 address (128 bits)
  if ((status = inet_pton(AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1)
  {
    fprintf(stderr, "inet_pton() failed for destination address.\nError message: %s", strerror(status));
    exit(EXIT_FAILURE);
  }

  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = htons(60);

  // Destination port number (16 bits)
  tcphdr.th_dport = htons(80);

  // Sequence number (32 bits)
  tcphdr.th_seq = htonl(0);

  // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
  tcphdr.th_ack = htonl(0);

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header + length of options, in 32-bit words
  tcphdr.th_off = (TCP_HDRLEN + opt_len) / 4;

  // Flags (8 bits)

  // FIN flag (1 bit)
  tcp_flags[0] = 0;

  // SYN flag (1 bit): set to 1
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
  tcphdr.th_sum = tcp6_checksum(iphdr, tcphdr, options, opt_len);

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header + TCP options)
  frame_length = 6 + 6 + 2 + IP6_HDRLEN + TCP_HDRLEN + opt_len;

  // Destination and Source MAC addresses
  memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
  memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

  // Next is ethernet type code (ETH_P_IPV6 for IPv6).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_IPV6 / 256;
  ether_frame[13] = ETH_P_IPV6 % 256;

  // Next is ethernet frame data (IPv6 header + TCP header).

  // IPv6 header
  memcpy(ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof(uint8_t));

  // TCP header
  memcpy(ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof(uint8_t));

  // TCP options
  memcpy(ether_frame + ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN, options, opt_len * sizeof(uint8_t));

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
  free(tcp_flags);
  free(options);

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
tcp6_checksum(struct ip6_hdr iphdr, struct tcphdr tcphdr, uint8_t *options, int opt_len)
{

  uint32_t lvalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  ptr = &buf[0]; // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy(ptr, &iphdr.ip6_src, sizeof(iphdr.ip6_src));
  ptr += sizeof(iphdr.ip6_src);
  chksumlen += sizeof(iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy(ptr, &iphdr.ip6_dst, sizeof(iphdr.ip6_dst));
  ptr += sizeof(iphdr.ip6_dst);
  chksumlen += sizeof(iphdr.ip6_dst);

  // Copy TCP length to buf (32 bits)
  lvalue = htonl(sizeof(tcphdr) + opt_len);
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

  // Copy TCP options to buf (variable length, but in 32-bit chunks)
  memcpy(ptr, options, opt_len * sizeof(uint8_t));
  ptr += opt_len;
  chksumlen += opt_len;

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
