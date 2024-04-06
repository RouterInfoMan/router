#pragma once

#include "protocols.h"
#include "lib.h"

#define IP_HEADER_LEN 20

struct iphdr* hdr_ip(char *buf);