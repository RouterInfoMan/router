#pragma once

#include "protocols.h"
#include "lib.h"

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

#define ETHER_HEADER_LEN 14 

struct ether_header* hdr_eth(char *buf);
void print_mac(uint8_t *mac);