#pragma once

#include "protocols.h"
#include "lib.h"
#include "ip.h"
#include "arp.h"

typedef struct {
    char *data;
    size_t len;
    uint32_t interface;
    uint32_t ip;
} packet_t;

typedef struct _node_t {
    packet_t *packet;
    struct _node_t *next;
} node_t;

typedef struct {
    node_t *head;
} packet_list_t;


packet_t *make_packet(char *data, size_t len, uint32_t interface, uint32_t ip);
void free_packet(packet_t *packet);

packet_list_t *make_packet_list();
void free_packet_list(packet_list_t *list);
void add_packet(packet_list_t *list, packet_t *packet);
int is_empty(packet_list_t *list);