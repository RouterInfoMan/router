#pragma once

#include "protocols.h"
#include "lib.h"
#include "eth.h"
#include "ip.h"

#include <string.h>
#include <arpa/inet.h>

#define ICMP_HEADER_LEN 8

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11




struct icmphdr* hdr_icmp(char *buf);
char *make_time_exceeded(char *buf, size_t len, int interface);
char *make_dest_unreachable(char *buf, size_t len, int interface);