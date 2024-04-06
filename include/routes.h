#pragma once

#include "protocols.h"
#include "lib.h"

void sort_routes(struct route_table_entry *rtable, int rtable_size);
struct route_table_entry* lookup_route(struct route_table_entry *rtable, int rtable_size, uint32_t dest_ip);
