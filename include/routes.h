#pragma once

#include "protocols.h"
#include "lib.h"
#include "lpm_trie.h"


void sort_routes(struct route_table_entry *rtable, int rtable_size);
struct route_table_entry* lookup_route(struct route_table_entry *rtable, int rtable_size, uint32_t dest_ip);
int lookup_route_via_trie(lpm_trie_t *trie, uint32_t dest_ip, uint32_t *next_hop, int *net_interface);
