#pragma once

#include "eth.h"
#include "ip.h"
#include "routes.h"
#include "lpm_trie.h"
#include "arp.h"
#include "icmp.h"
#include "protocols.h"
#include "lib.h"

void print_debug_eth_hdr(struct ether_header *eth_hdr);
void print_debug_arp_hdr(struct arp_header* arp_hdr);
void print_debug_ip_hdr(struct iphdr *ip_hdr);
void print_debug_icmp_hdr(struct icmphdr *icmp_hdr);
