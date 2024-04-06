#include "icmp.h"

struct icmphdr* hdr_icmp(char *buf) {
    return (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
}