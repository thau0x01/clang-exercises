# Clang Exercises
This repository contains programs I developed while practicizing coding in C for linux.

## Project structure

```
.
├── README.md
└── net
    ├── 00_arp_eth_frames
    │   ├── arp.c
    │   ├── arp_receive.c
    │   ├── receive_router_advertisement.c
    │   ├── send_router_advertisement.c
    │   ├── send_router_solicitation.c
    │   └── tcp_udp_icmp_traceroute.c
    ├── 01_raw_sockets
    │   ├── icmp.c
    │   ├── tcp.c
    │   ├── tcp_http_get.c
    │   └── udp.c
    ├── 02_layer2_raw
    │   ├── icmp4_l2.c
    │   ├── icmp4_l2_ping.c
    │   ├── tcp4_http_get_l2.c
    │   ├── tcp4_l2.c
    │   └── udp4_l2.c
    ├── 03_cooked_packets
    │   ├── icmp4_cooked.c
    │   ├── tcp4_cooked.c
    │   ├── tcp4_cooked_http_get.c
    │   └── udp4_cooked.c
    ├── 05_fragmentation
    │   ├── send_icmp4_fragmented_packet.c
    │   ├── send_tcp4_framented_packet.c
    │   └── send_udp4_fragmented_packet.c
    ├── 06_ipv4_tcp_options
    │   ├── tcp4_2ip-opts_2tcp_opts.c
    │   ├── tcp4_maxseg-security.c
    │   ├── tcp4_maxseg-timestamp.c
    │   ├── tcp_max_segment_option.c
    │   └── tcp_max_segment_option_and_timestamp.c
    ├── 07_ipv6_intro
    │   ├── icmp6_ancillary1.c
    │   ├── icmp6_ancillary2.c
    │   ├── icmp6_ancillary3.c
    │   ├── ipv6_neightboor_advertisement.c
    │   ├── ipv6_neightboor_solicitation.c
    │   ├── ipv6_receive_neightboor_solicitation.c
    │   ├── ipv6_receive_router_advertisement.c
    │   ├── ipv6_router_advertisement.c
    │   └── ipv6_router_solicitation.c
    ├── 08_ipv6_ethernet_frames
    │   ├── icmp6.c
    │   ├── icmp6_ping.c
    │   ├── tcp6_http_get.c
    │   ├── tcp6_syn_packet.c
    │   └── udp6.c
    ├── 09_ipv6_cooked_packets
    │   ├── icmp6_cooked.c
    │   ├── tcp6_cooked.c
    │   ├── tcp6_cooked_http_get.c
    │   └── udp6_cooked.c
    ├── 10_ipv6_over_ipv4
    │   ├── icmp6_6to4.c
    │   ├── icmp6_6to4_ping.c
    │   ├── tcp6_6to4.c
    │   ├── tcp6_6to4_http_get.c
    │   └── udp6_6to4.c
    ├── 11_ipv6_fragmentation
    │   ├── data
    │   ├── icmp6_6to4_frag.c
    │   ├── icmp6_frag.c
    │   ├── tcp6_6to4_frag.c
    │   ├── tcp6_frag.c
    │   ├── udp6_6to4_frag.c
    │   └── udp6_frag.c
    ├── 12_ipv6_with_tcp_options
    │   ├── tcp6_maxseg.c
    │   └── tcp6_maxseg_tsopt.c
    ├── 13_ipv6_tcp_hop_by_hop_ext
    │   ├── data
    │   └── tcp6_hop_frag.c
    ├── 14_ipv6_authentication_ext_header
    │   ├── data
    │   ├── tcp6_hop_auth-tr_frag.c
    │   └── tcp6_hop_auth-tun_frag.c
    ├── 15_encapsulating_security_payload_ESP_ext_header
    │   ├── data
    │   ├── tcp6_hop_esp-tr_frag.c
    │   └── tcp6_hop_esp-tun_frag.c
    ├── 16_destination_ext_header
    │   ├── data
    │   └── tcp6_hop_dst_frag.c
    ├── 17_routing_extension_header
    │   ├── data
    │   └── tcp6_hop_route3_frag.c
    ├── data
```
