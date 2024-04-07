#include "arp.h"

struct arp_header* hdr_arp(char *buf)
{
    return (struct arp_header *) (buf + sizeof(struct ether_header));
}

struct arp_table_entry *lookup_arp_table(struct arp_table_entry *arp_table, int arp_table_len, uint32_t ip)
{
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

void add_new_entry(struct arp_table_entry *arp_table, int *arp_table_len, uint32_t ip, uint8_t *mac)
{   
    struct arp_table_entry *entry = lookup_arp_table(arp_table, *arp_table_len, ip);
    if (!entry) {
        arp_table[*arp_table_len].ip = ip;
        memcpy(arp_table[*arp_table_len].mac, mac, 6);
        (*arp_table_len)++;
        return;
    }
    // Update entry
    memcpy(entry->mac, mac, 6);
}

char *make_arp_request(uint32_t lookup_ip, uint8_t *interface_mac, uint32_t interface_ip)
{
    char *packet = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));

    struct ether_header *eth_hdr = hdr_eth(packet);
    struct arp_header *arp_hdr = hdr_arp(packet);

    // eth header
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    memcpy(eth_hdr->ether_shost, interface_mac, 6);
    memset(eth_hdr->ether_dhost, 0xff, 6);

    // arp req header
    arp_hdr->htype = htons(ARP_HTYPE_ETHERNET);
    arp_hdr->ptype = htons(ETHERTYPE_IP);
    arp_hdr->hlen = 6;
    arp_hdr->plen = 4;
    arp_hdr->op = htons(ARPOP_REQUEST);
    // targets
    memcpy(arp_hdr->sha, interface_mac, 6);
    arp_hdr->spa = interface_ip;
    memset(arp_hdr->tha, 0, 6);
    arp_hdr->tpa = lookup_ip;

    return packet;
}
char *make_arp_reply(uint8_t *request_mac, uint32_t request_ip, uint8_t *interface_mac, uint32_t interface_ip) 
{
    char *packet = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));

    struct ether_header *eth_hdr = hdr_eth(packet);
    struct arp_header *arp_hdr = hdr_arp(packet);

    // eth header
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    memcpy(eth_hdr->ether_shost, interface_mac, 6);
    memcpy(eth_hdr->ether_dhost, request_mac, 6);

    // arp reply header
    arp_hdr->htype = htons(ARP_HTYPE_ETHERNET);
    arp_hdr->ptype = htons(ETHERTYPE_IP);
    arp_hdr->hlen = 6;
    arp_hdr->plen = 4;
    arp_hdr->op = htons(ARPOP_REPLY);
    // targets
    memcpy(arp_hdr->sha, interface_mac, 6);
    arp_hdr->spa = interface_ip;
    memcpy(arp_hdr->tha, request_mac, 6);
    arp_hdr->tpa = request_ip;

    return packet;
}