#include "lpm_trie.h"


trie_node_t *alloc_node()
{
    trie_node_t *node = (trie_node_t *)malloc(sizeof(trie_node_t));
    node->l = node->r = NULL;
    node->net_interface = -1;
    node->next_hop = 0;

    return node;
}

void free_node(trie_node_t *node)
{
    if (node == NULL)
        return;

    free_node(node->l);
    free_node(node->r);
    free(node);
}

lpm_trie_t *lpm_trie_create()
{
    lpm_trie_t *trie = (lpm_trie_t *)malloc(sizeof(lpm_trie_t));
    trie->root = alloc_node(); // 0.0.0.0 default gateway

    return trie;
}

void lpm_trie_destroy(lpm_trie_t *trie)
{
    free_node(trie->root);
    free(trie);
}

void lpm_trie_insert(lpm_trie_t *trie, uint32_t prefix, int8_t mask_len, uint32_t next_hop, int net_interface)
{
    trie_node_t *node = trie->root;
    // print_ip(prefix);
    for (int i = 31; i >= 32 - mask_len; i--) {
        // printf("%d\n", (prefix >> i) & 1);
        if ((prefix >> i) & 1) {
            if (node->r == NULL) {
                node->r = alloc_node();
            }
            node = node->r;
        } else {
            if (node->l == NULL) {
                node->l = alloc_node();
            }
            node = node->l;
        }
    }
    node->net_interface = net_interface;
    node->next_hop = next_hop;
}

int lpm_trie_lookup(lpm_trie_t *trie, uint32_t ip, uint32_t *next_hop, int *net_interface) {
    trie_node_t *node = trie->root;
    int found = 0;

    for (int i = 31; i >= 0; i--) {
        if ((ip >> i) & 1) {
            node = node->r;
        } else {
            node = node->l;
        }

        if (node == NULL) {
            return found;
        }

        if (node->net_interface != -1) {
            *net_interface = node->net_interface;
            *next_hop = node->next_hop;
            found = 1;
        }
    }

    return found;
}