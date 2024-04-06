#pragma once

#include "protocols.h"
#include "lib.h"

#define ICMP_HEADER_LEN 8

struct icmphdr* hdr_icmp(char *buf);