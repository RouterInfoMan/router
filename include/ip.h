#pragma once

#include "protocols.h"
#include "lib.h"

#include <string.h>
#include <arpa/inet.h>

#define IP_HEADER_LEN 20
#define IP_FWD_GOOD 0
#define IP_FWD_FOR_ROUTER 1
#define IP_FWD_BAD_CHECKSUM 2
#define IP_FWD_TIME_EXCEEDED 3
#define IP_FWD_NO_ROUTE 4


struct iphdr* hdr_ip(char *buf);
void write_defaults_iphdr(struct iphdr *ip_hdr);

uint32_t get_interface_ip_uint32(int interface);
void print_ip(unsigned int ip);