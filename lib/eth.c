#include "eth.h"

struct ether_header* hdr_eth(char *buf) {
    return (struct ether_header *) buf;
}