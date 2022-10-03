/*  Copyright (C) 2013-2015  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Send an IPv6 TCP packet via raw socket at the link layer (ethernet frame).
// with a large payload requiring fragmentation. Include a hop-by-hop options
// extension header with a router alert option. Include an authentication
// extension header (with some random bogus integrity check value (ICV)).
// See Section 3 of RFC 2402 for information on properly calculating ICV.
// The authentication header is used here in tunnel mode.
// Need to have destination MAC address.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_IPV6, IPPROTO_HOPOPTS, IPPROTO_AH, IPPROTO_TCP, IPPROTO_FRAGMENT, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#define __FAVOR_BSD           // Use BSD format of tcp header
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

// Define a struct for hop-by-hop header, excluding options.
typedef struct _hop_hdr hop_hdr;
struct _hop_hdr {
  uint8_t nxt_hdr;
  uint8_t hdr_len;
};

// Define a struct for authentication header, excluding authentication data.
typedef struct _auth_hdr auth_hdr;
struct _auth_hdr {
  uint8_t nxt_hdr;
  uint8_t pay_len;
  u_int16_t reserved;
  u_int32_t spi;
  u_int32_t seq;
};

// Define some constants.
#define ETH_HDRLEN 14         // Ethernet header length
#define IP6_HDRLEN 40         // IPv6 header length
#define HOP_HDRLEN 2          // Hop-by-hop header length, excluding options
#define TCP_HDRLEN 20         // TCP header length, excludes options data
#define FRG_HDRLEN 8          // IPv6 fragment header
#define MAX_FRAGS 3119        // Maximum number of packet fragments
#define MAX_HBHOPTIONS 10     // Maximum number of extension header options
#define MAX_HBHOPTLEN 256     // Maximum length of a hop-by-hop option (some large value)
#define ATH_HDRLEN 12         // Authentication header length, excludes authentication data

// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t tcp6_checksum (struct ip6_hdr, struct tcphdr, uint8_t *, int);
int option_pad (int *, uint8_t *, int *, int, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
uint8_t **allocate_ustrmemp (int);
int *allocate_intmem (int);

int
main (int argc, char **argv) {

  int i, j, n, indx, status, frame_length, sd, bytes;
  int hoplen, mtu, *frag_flags, *tcp_flags, c, nframes, offset[MAX_FRAGS], len[MAX_FRAGS];
  hop_hdr hophdr;
  auth_hdr authhdr;
  int hbh_optpadlen;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip6_hdr iphdr, newiphdr;
  struct tcphdr tcphdr;
  struct ip6_frag fraghdr;
  int payloadlen, fragbufferlen;
  uint8_t *payload, *fragbuffer, *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in6 *ipv6;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;
  FILE *fi;

  int hbh_nopt;  // Number of hop-by-hop options
  int hbh_opt_totlen;  // Total length of hop-by-hop options
  int *hbh_optlen;  // Hop-by-hop option length: hbh_optlen[option #] = int
  uint8_t **hbh_options;  // Hop-by-hop options data: hbh_options[option #] = uint8_t *
  int *hbh_x, *hbh_y;  // Alignment requirements for hop-by-hop options: hbh_x[option #] = int, hbh_y[option #] = int

  uint8_t *auth_data;  // Authentication header data (integrity check value (ICV)): auth_data = uint8_t *
  int auth_len;  // Authentication header data length

  // Allocate memory for various arrays.
  hbh_optlen = allocate_intmem (MAX_HBHOPTIONS);  // hbh_optlen[option #] = int
  hbh_options = allocate_ustrmemp (MAX_HBHOPTIONS);  // hbh_options[option #] = uint8_t *
  for (i=0; i<MAX_HBHOPTIONS; i++) {
    hbh_options[i] = allocate_ustrmem (MAX_HBHOPTLEN);
  }
  hbh_x = allocate_intmem (MAX_HBHOPTIONS);  // Hop-by-hop option alignment requirement x (of xN + y): hbh_x[option #] = int
  hbh_y = allocate_intmem (MAX_HBHOPTIONS);  // Hop-by-hop option alignment requirement y (of xN + y): hbh_y[option #] = int
  auth_data = allocate_ustrmem (0xff * 0xffff);  // auth_data = uint8_t *
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (INET6_ADDRSTRLEN);
  src_ip = allocate_strmem (INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
  tcp_flags = allocate_intmem (8);
  payload = allocate_ustrmem (IP_MAXPACKET);
  frag_flags = allocate_intmem (2);

  // Interface to send packet through.
  strcpy (interface, "eno1");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to get interface maximum transmission unit (MTU).
  memset (&ifr, 0, sizeof (ifr));
  strcpy (ifr.ifr_name, interface);
  if (ioctl (sd, SIOCGIFMTU, &ifr) < 0) {
    perror ("ioctl() failed to get MTU ");
    return (EXIT_FAILURE);
  }
  mtu = ifr.ifr_mtu;
  printf ("Current MTU of interface %s is: %i\n", interface, mtu);

  // Use ioctl() to look up interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close (sd);

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  // Report source MAC address to stdout.
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

  // Set destination MAC address: you need to fill these out
  dst_mac[0] = 0xff;
  dst_mac[1] = 0xff;
  dst_mac[2] = 0xff;
  dst_mac[3] = 0xff;
  dst_mac[4] = 0xff;
  dst_mac[5] = 0xff;

  // Source IPv6 address: you need to fill this out
  strcpy (src_ip, "2001:db8::214:51ff:fe2f:1556");

  // Destination URL or IPv6 address: you need to fill this out
  strcpy (target, "ipv6.google.com");

  // Number of hop-by-hop extension header options.
  hbh_nopt = 1;

  // Hop-by-hop option: router alert (with bogus value)
  // Alignment requirement is 2n+0 for router alert. See Section 2.1 of RFC 2711.
  hbh_x[0] = 2;
  hbh_y[0] = 0;
  // hbh_options[option #] = uint8_t *
  hbh_options[0][0] = 5;  // Option Type: router alert
  hbh_options[0][1] = 2;  // Length of Option Data field
  hbh_options[0][2] = 0;  // Option Data: some unassigned IANA value, you
  hbh_options[0][3] = 5;  // should select what you want.
  // Hop-by-hop option length.
  hbh_optlen[0] = 4;  // Hop-by-hop header option length (excludes hop-by-hop header itself (2 bytes))

  // Calculate total length of hop-by-hop options.
  hbh_opt_totlen = 0;
  for (i=0; i<hbh_nopt; i++) {
    hbh_opt_totlen += hbh_optlen[i];
  }

  // Determine total padding needed to align and pad hop-by-hop options (Section 4.2 of RFC 2460).
  indx = 0;
  if (hbh_nopt > 0) {
    indx += HOP_HDRLEN; // Account for hop-by-hop header (Next Header and Header Length)
    for (i=0; i<hbh_nopt; i++) {
      // Add any necessary alignment for option i
      while ((indx % hbh_x[i]) != hbh_y[i]) {
        indx++;
      }
      // Add length of option i
      indx += hbh_optlen[i];
    }
    // Now pad last option to next 8-byte boundary (Section 4.2 of RFC 2460).
    while ((indx % 8) != 0) {
      indx++;
    }

    // Total of alignments and final padding = indx - HOP_HDRLEN - total length of hop-by-hop (non-pad) options
    hbh_optpadlen = indx - HOP_HDRLEN - hbh_opt_totlen;

    // Determine length of hop-by-hop header in units of 8 bytes, excluding first 8 bytes.
    // Section 4.3 of RFC 2460.
    i = (indx - 8) / 8;
    if (i < 0) {
      i = 0;
    }
    hophdr.hdr_len = i;
  } else {
    hbh_opt_totlen = 0;
    hbh_optpadlen = 0;
  }

  // Print some information about hop-by-hop options.
  printf ("Number of hop-by-hop options: %i\n", hbh_nopt);
  printf ("Total length of hop-by-hop options, excluding 2-byte hop-by-hop header and padding: %i\n", hbh_opt_totlen);
  printf ("Total length of hop-by-hop alignment padding and end-padding: %i\n", hbh_optpadlen);

  // Authentication data (integrity check value (ICV))
  auth_data[0] = 34;  // Made-up numbers used here. You need to compute as per Section 3 of RFC 2402.
  auth_data[1] = 2;
  auth_data[2] = 0;
  auth_data[3] = 16;
  auth_data[4] = 66;
  auth_data[5] = 99;
  auth_data[6] = 11;
  auth_data[7] = 2;
  auth_data[8] = 31;
  auth_data[9] = 0;
  auth_data[10] = 8;
  auth_data[11] = 23;

  // Length of authentication data (ICV) above.
  auth_len = 12;

  // Authentication header payload length (in units of 32-bits) less 2 (Section 2.2 of RFC 2402).
  authhdr.pay_len = (ATH_HDRLEN / 4) + (auth_len / 4) - 2;

  // Add padding, if required. Contents of padding is unimportant. We'll use zero.
  // For IPv6, AH header must be multiple of 64 bits (8 bytes). See Section 3.3.3.2.1 of RFC 2402.
  while (((ATH_HDRLEN + auth_len)%8) != 0) {
    auth_data[auth_len] = 0;
    auth_len++;
  }

  // Print some information about authentication header.
  printf ("Length of authentication data (integrity check value (ICV)): %i\n", auth_len);
  printf ("Total length of authentication header (including data and padding): %i\n", ATH_HDRLEN + auth_len);

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_RAW;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv6 = (struct sockaddr_in6 *) res->ai_addr;
  tmp = &(ipv6->sin6_addr);
  if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for target.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
  device.sll_halen = 6;

  // Get TCP data.
  i = 0;
  fi = fopen ("data", "r");
  if (fi == NULL) {
    printf ("Can't open file 'data'.\n");
    exit (EXIT_FAILURE);
  }
  while ((n=fgetc (fi)) != EOF) {
    payload[i] = n;
    i++;
  }
  fclose (fi);
  payloadlen = i;
  printf ("Upper layer protocol header length (bytes): %i\n", TCP_HDRLEN);
  printf ("Payload length (bytes): %i\n", payloadlen);

  // Length of hop-by-hop header, options, and padding.
  if (hbh_nopt > 0) {
    hoplen = HOP_HDRLEN + hbh_opt_totlen + hbh_optpadlen;
  } else {
    hoplen = 0;
  }

  // Authentication header is part of fragmentable portion of packet.
  // See Section 3.1.2, "Tunnel Mode", of RFC 4302.
  fragbufferlen = ATH_HDRLEN + auth_len + IP6_HDRLEN + hoplen + TCP_HDRLEN + payloadlen;
  printf ("Total fragmentable data (bytes): %i\n", fragbufferlen);

  // Allocate memory for the fragmentable portion.
  fragbuffer = allocate_ustrmem (fragbufferlen);

  // Determine how many ethernet frames we'll need.
  memset (len, 0, MAX_FRAGS * sizeof (int));
  memset (offset, 0, MAX_FRAGS * sizeof (int));
  i = 0;
  c = 0;  // Variable c is index to buffer, which contains upper layer protocol header and data.
  while (c < fragbufferlen) {

    // Do we still need to fragment remainder of fragmentable portion?
    if ((fragbufferlen - c) > (mtu - IP6_HDRLEN - FRG_HDRLEN)) {  // Yes
      len[i] = mtu - IP6_HDRLEN - FRG_HDRLEN;  // len[i] is amount of fragmentable part we can include in this frame.

    } else {  // No
      len[i] = fragbufferlen - c;  // len[i] is amount of fragmentable part we can include in this frame.
    }
    c += len[i];

    // If not last fragment, make sure we have an even number of 8-byte blocks.
    // Reduce length as necessary.
    if (c < (fragbufferlen - 1)) {
      while ((len[i]%8) > 0) {
        len[i]--;
        c--;
      }
    }
    printf ("Frag: %i,  Data (bytes): %i,  Data Offset (8-byte blocks): %i\n", i, len[i], offset[i]);
    i++;
    offset[i] = (len[i-1] / 8) + offset[i-1];
  }
  nframes = i;
  printf ("Total number of frames to send: %i\n", nframes);

  // IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits)
  iphdr.ip6_plen = htons (hoplen + TCP_HDRLEN + payloadlen);

  // Next header (8 bits): 6 for TCP
  // We'll change this later, otherwise TCP checksum will be wrong.
  iphdr.ip6_nxt = IPPROTO_TCP;

  // Hop limit (8 bits): default to maximum value
  iphdr.ip6_hops = 255;

  // Source IPv6 address (128 bits)
  if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
    fprintf (stderr, "inet_pton() failed for source address.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv6 address (128 bits)
  if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Hop-by-hop extension header

  // Next header (8 bits): 6 for TCP
  hophdr.nxt_hdr = IPPROTO_TCP;

  // Length of hop-by-hop options header (units of 8 bytes), excluding 1st 8 bytes.
  hophdr.hdr_len = 0;

  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = htons (80);

  // Destination port number (16 bits)
  tcphdr.th_dport = htons (80);

  // Sequence number (32 bits)
  tcphdr.th_seq = htonl (0);

  // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
  tcphdr.th_ack = htonl (0);

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr.th_off = TCP_HDRLEN / 4;

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
  for (i=0; i<8; i++) {
    tcphdr.th_flags += (tcp_flags[i] << i);
  }

  // Window size (16 bits)
  tcphdr.th_win = htons (65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons (0);

  // TCP checksum (16 bits)
  tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr, payload, payloadlen);

  // Next header (8 bits): 0 for hop-by-hop extension header
  iphdr.ip6_nxt = IPPROTO_HOPOPTS;

  // New IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  newiphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits)
  // newiphdr.ip6_plen is set for each fragment in loop below.

  // Next header (8 bits)
  if (nframes == 1)  {
    newiphdr.ip6_nxt = IPPROTO_AH;  // 51 for authentication extension header
  } else {
    newiphdr.ip6_nxt = IPPROTO_FRAGMENT;  // 44 for Fragmentation extension header
  }

  // Hop limit (8 bits): default to maximum value
  newiphdr.ip6_hops = 255;

  // Source IPv6 address (128 bits)
  if ((status = inet_pton (AF_INET6, src_ip, &(newiphdr.ip6_src))) != 1) {
    fprintf (stderr, "inet_pton() failed for source address for new IP header.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv6 address (128 bits)
  if ((status = inet_pton (AF_INET6, dst_ip, &(newiphdr.ip6_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed for destination address for new IP header.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Authentication extension header
  authhdr.nxt_hdr = IPPROTO_IPV6;  // 41 for IPv6 header
  authhdr.reserved = htons (0u);
  authhdr.spi = htonl (51413ul);  // Security parameters index (Section 2.4 of RFC 2402): you set this
  authhdr.seq = htonl (31415ul);  // Sequence number (Section 2.5 of RFC 2402): you set this

  // Build buffer array containing fragmentable portion.

  // Authentication extension header
  c = 0;
  memcpy (fragbuffer, &authhdr, ATH_HDRLEN * sizeof (uint8_t));  // Authentication header, excluding authentication data
  c += ATH_HDRLEN;
  memcpy (fragbuffer + c, auth_data, auth_len * sizeof (uint8_t));  // Authentication data
  c += auth_len;

  // Original IPv6 header
  memcpy (fragbuffer + c, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
  c += IP6_HDRLEN;

  // Add hop-by-hop header and options, if specified.
  indx = 0;  // Index is zero at start of hop-by-hop header.
  if (hbh_nopt > 0) {

    // Copy hop-by-hop extension header (without options) to ethernet frame.
    memcpy (fragbuffer + c, &hophdr, HOP_HDRLEN * sizeof (uint8_t));
    c += HOP_HDRLEN;
    indx += HOP_HDRLEN;

    // Copy hop-by_hop extension header options to ethernet frame.
    for (j=0; j<hbh_nopt; j++) {
      // Pad as needed to achieve alignment requirements for option j (Section 4.2 of RFC 2460).
      option_pad (&indx, fragbuffer, &c, hbh_x[j], hbh_y[j]);

      // Copy hop-by-hop option to ethernet frame.
      memcpy (fragbuffer + c, hbh_options[j], hbh_optlen[j] * sizeof (uint8_t));
      c += hbh_optlen[j];
      indx += hbh_optlen[j];
    }

    // Now pad last option to next 8-byte boundary (Section 4.2 of RFC 2460).
    option_pad (&indx, fragbuffer, &c, 8, 0);
  }

  // TCP header
  memcpy (fragbuffer + c, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
  c += TCP_HDRLEN;

  // TCP data
  memcpy (fragbuffer + c, payload, payloadlen * sizeof (uint8_t));
  c += payloadlen;

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Loop through fragments.
  for (i=0; i<nframes; i++) {

    // Set ethernet frame contents to zero initially.
    memset (ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));

    // Index of ethernet frame.
    c = 0;

    // Fill out ethernet frame header.

    // Copy destination and source MAC addresses to ethernet frame.
    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

    // Next is ethernet type code (ETH_P_IPV6 for IPv6).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_IPV6 / 256;
    ether_frame[13] = ETH_P_IPV6 % 256;
    c += ETH_HDRLEN;

    // Next is ethernet frame data

    // Payload length (16 bits): See 3 of RFC 2460.
    if (nframes == 1) {
      newiphdr.ip6_plen = htons (len[i]);
    } else {
      newiphdr.ip6_plen = htons (FRG_HDRLEN + len[i]);
    }

    // Copy new IPv6 header to ethernet frame.
    memcpy (ether_frame + c, &newiphdr, IP6_HDRLEN * sizeof (uint8_t));
    c += IP6_HDRLEN;

    // Fill out and copy fragmentation extension header, if necessary, to ethernet frame.
    if (nframes > 1) {
      fraghdr.ip6f_nxt = IPPROTO_AH;  // Next header is authentication header.
      fraghdr.ip6f_reserved = 0;  // Reserved
      frag_flags[1] = 0;  // Reserved
      if (i < (nframes - 1)) {
        frag_flags[0] = 1;  // More fragments to follow
      } else {
        frag_flags[0] = 0;  // This is the last fragment
      }
      fraghdr.ip6f_offlg = htons ((offset[i] << 3) + frag_flags[0] + (frag_flags[1] <<1));
      fraghdr.ip6f_ident = htonl (31415);
      memcpy (ether_frame + c, &fraghdr, FRG_HDRLEN * sizeof (uint8_t));
      c += FRG_HDRLEN;
    }

    // Copy fragmentable portion of packet to ethernet frame.
    memcpy (ether_frame + c, fragbuffer + (offset[i] * 8), len[i] * sizeof (uint8_t));
    c += len[i];

    // Ethernet frame length
    frame_length = c;

    // Send ethernet frame to socket.
    printf ("Sending fragment: %i\n", i);
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
      perror ("sendto() failed");
      exit (EXIT_FAILURE);
    }
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (tcp_flags);
  free (payload);
  free (frag_flags);
  free (fragbuffer);
  free (hbh_optlen);
  for (i=0; i<MAX_HBHOPTIONS; i++) {
    free (hbh_options[i]);
  }
  free (hbh_options);
  free (hbh_x);
  free (hbh_y);
  free (auth_data);

  return (EXIT_SUCCESS);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum is not guaranteed to preclude collisions.
uint16_t
checksum (uint16_t *addr, int len) {

  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv6 TCP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen) {

  uint32_t lvalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;
  int i;

  memset (buf, 0, IP_MAXPACKET * sizeof (uint8_t));

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy TCP length to buf (32 bits)
  lvalue = htonl (sizeof (tcphdr) + payloadlen);
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  i = 0;
  while (((payloadlen+i)%2) != 0) {
    i++;
    chksumlen++;
    ptr++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Provide padding as needed to achieve alignment requirements of hop-by-hop or destination option.
int
option_pad (int *indx, uint8_t *padding, int *c, int x, int y) {

  int needpad;

  // Find number of padding bytes needed to achieve alignment requirements for option (Section 4.2 of RFC 2460).
  // Alignment is expressed as xN + y, which means the start of the option must occur at xN + y bytes
  // from the start of the hop-by-hop or destination header, where N is integer 0, 1, 2, ...etc.
  needpad = 0;
  while (((*indx + needpad) % x) != y) {
    needpad++;
  }

  // If required padding = 1 byte, we use Pad1 option.
  if (needpad == 1) {
    padding[*c] = 0;  // Padding option type: Pad1
    (*indx)++;
    (*c)++;

  // If required padding is > 1 byte, we use PadN option.
  } else if (needpad > 1) {
    padding[*c] = 1;  // Padding option type: PadN
    (*indx)++;
    (*c)++;
    padding[*c] = needpad - 2;  // PadN length: N - 2
    (*indx)++;
    (*c)++;
    memset (padding + (*c), 0, (needpad - 2) * sizeof (uint8_t));
    (*indx) += needpad - 2;
    (*c) += needpad - 2;
  }

  return (EXIT_SUCCESS);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of pointers to arrays of unsigned chars.
uint8_t **
allocate_ustrmemp (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmemp().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t **) malloc (len * sizeof (uint8_t *));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t *));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmemp().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}
