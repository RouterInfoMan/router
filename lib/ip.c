#include "ip.h"

struct iphdr* hdr_ip(char *buf) {
    return (struct iphdr *) (buf + sizeof(struct ether_header));
}
