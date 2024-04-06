#pragma once

// this is inneficient
// TODO make this trie collapse prefixes
#include "protocols.h"
#include <stdlib.h>
#include <stdint.h>

typedef struct _trie_node_t {
    struct _trie_node_t *l, *r;
    int net_interface; // -1 if not set
    uint32_t next_hop;
} trie_node_t;

typedef struct {
    trie_node_t *root;
} lpm_trie_t;

lpm_trie_t *lpm_trie_create();
void lpm_trie_destroy(lpm_trie_t *trie);
void lpm_trie_insert(lpm_trie_t *trie, uint32_t prefix, uint32_t mask_len, uint32_t next_hop, int net_interface);
int lpm_trie_lookup(lpm_trie_t *trie, uint32_t ip, uint32_t *next_hop, int *net_interface);