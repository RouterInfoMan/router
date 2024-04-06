#pragma once

#include "protocols.h"
#include "lib.h"
#include "eth.h"

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

#define ARP_HTYPE_ETHERNET 1

#define ARP_HEADER_LEN 28

struct arp_header* hdr_arp(char *buf);
struct arp_table_entry *lookup_arp_table(arp_table_entry *arp_table, int arp_table_len, uint32_t ip);
void add_new_entry(struct arp_table_entry *arp_table, int *arp_table_len, uint32_t ip, uint8_t *mac);

char *make_arp_reply(uint8_t *request_mac, uint32_t request_ip, uint8_t *interface_mac, uint32_t interface_ip);
char *make_arp_request(uint32_t lookup_ip, uint8_t *interface_mac, uint32_t interface_ip);