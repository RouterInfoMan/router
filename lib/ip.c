#include "ip.h"

struct iphdr* hdr_ip(char *buf) {
    return (struct iphdr *) (buf + sizeof(struct ether_header));
}

void write_defaults_iphdr(struct iphdr *ip_hdr)
{
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->id = htons(1);
    ip_hdr->frag_off = htons(0);
    ip_hdr->check = 0;
    ip_hdr->ttl = 64;
}

void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

uint32_t get_interface_ip_uint32(int interface)
{
	return inet_addr(get_interface_ip(interface));
}