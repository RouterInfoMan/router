#include "routes.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int route_comp(const void *ra, const void *rb)
{
    struct route_table_entry *a = (struct route_table_entry *)ra;
    struct route_table_entry *b = (struct route_table_entry *)rb;

    uint32_t haprefix = ntohl(a->prefix & a->mask);
    uint32_t hbprefix = ntohl(b->prefix & b->mask);

    uint32_t hamask = ntohl(a->mask);
    uint32_t hbmask = ntohl(b->mask);

    if (haprefix < hbprefix) {
        return -1;
    } else if (haprefix > hbprefix) {
        return 1;
    } else {
        if (hamask < hbmask) {
            return -1;
        } else if (hamask > hbmask) {
            return 1;
        } else {
            return 0;
        }
    }

}

void print_ipv4(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

void sort_routes(struct route_table_entry *rtable, int rtable_size)
{
    qsort(rtable, rtable_size, sizeof(struct route_table_entry), route_comp);
}
struct route_table_entry* lookup_route(struct route_table_entry *rtable, int rtable_size, uint32_t dest_ip)
{
    int left = 0, right = rtable_size - 1;
    struct route_table_entry *best_route = NULL;

    while (left <= right) {
        int mid = (left + right) / 2;
        // print_ipv4(ntohl(dest_ip));
        // printf("mid-1\n");
        // print_ipv4(ntohl(rtable[mid-1].prefix));
        // print_ipv4(ntohl(rtable[mid-1].mask));
        // printf("mid\n");
        // print_ipv4(ntohl(rtable[mid].prefix));
        // print_ipv4(ntohl(rtable[mid].mask));
        // printf("mid+1\n");
        // print_ipv4(ntohl(rtable[mid+1].prefix));
        // print_ipv4(ntohl(rtable[mid+1].mask));
        // printf("\n");

        if (ntohl(dest_ip & rtable[mid].mask) == ntohl(rtable[mid].prefix & rtable[mid].mask)) {
            best_route = &rtable[mid];
            left = mid + 1;
        }
        else if (ntohl(dest_ip & rtable[mid].mask) > ntohl(rtable[mid].prefix & rtable[mid].mask)) {
            left = mid + 1;
        }
        else {
            right = mid - 1;
        }
    }

    return best_route;
}

int lookup_route_via_trie(lpm_trie_t *trie, uint32_t dest_ip, uint32_t *next_hop, int *net_interface)
{
    return lpm_trie_lookup(trie, dest_ip, next_hop, net_interface);
}