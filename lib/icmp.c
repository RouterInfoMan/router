#include "icmp.h"

struct icmphdr* hdr_icmp(char *buf) {
    return (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
}
char *make_dest_unreachable(char *buf, size_t len, int interface)
{
    char *packet = malloc(ETHER_HEADER_LEN +
                          IP_HEADER_LEN +
                          ICMP_HEADER_LEN +
                          IP_HEADER_LEN +
                          ICMP_HEADER_LEN);
    
    struct ether_header *eth_hdr_pkt = hdr_eth(packet);
    struct iphdr *ip_hdr_pkt = hdr_ip(packet);
    struct icmphdr *icmp_hdr_pkt = hdr_icmp(packet);

    struct iphdr *ip_hdr = hdr_ip(buf);

    // icmp payload
     memcpy(((char *)icmp_hdr_pkt) + ICMP_HEADER_LEN, ip_hdr, IP_HEADER_LEN + 8);

    

    // icmp header
    icmp_hdr_pkt->type = ICMP_TYPE_DEST_UNREACH;
    icmp_hdr_pkt->code = 0;
    icmp_hdr_pkt->checksum = 0;
    icmp_hdr_pkt->checksum = htons(checksum((uint16_t *) icmp_hdr_pkt, IP_HEADER_LEN + 2 * ICMP_HEADER_LEN));

    // ip payload
    write_defaults_iphdr(ip_hdr_pkt);
    ip_hdr_pkt->tot_len = htons(2 * IP_HEADER_LEN + 2 * ICMP_HEADER_LEN);
    ip_hdr_pkt->protocol = IPPROTO_ICMP;
    ip_hdr_pkt->saddr = get_interface_ip_uint32(interface);
    ip_hdr_pkt->daddr = ip_hdr->saddr;
    ip_hdr_pkt->check = 0;
    ip_hdr_pkt->check = htons(checksum((uint16_t *) ip_hdr_pkt, ntohs(ip_hdr_pkt->tot_len)));

    // eth header
    eth_hdr_pkt->ether_type = htons(ETHERTYPE_IP);
    memcpy(eth_hdr_pkt->ether_shost, hdr_eth(buf)->ether_dhost, 6);
    memcpy(eth_hdr_pkt->ether_dhost, hdr_eth(buf)->ether_shost, 6);

    return packet;
}

char *make_time_exceeded(char *buf, size_t len, int interface)
{
    char *packet = malloc(ETHER_HEADER_LEN +
                          IP_HEADER_LEN +
                          ICMP_HEADER_LEN +
                          IP_HEADER_LEN +
                          ICMP_HEADER_LEN);
    
    struct ether_header *eth_hdr_pkt = hdr_eth(packet);
    struct iphdr *ip_hdr_pkt = hdr_ip(packet);
    struct icmphdr *icmp_hdr_pkt = hdr_icmp(packet);

    struct ether_header *eth_hdr = hdr_eth(buf);
    struct iphdr *ip_hdr = hdr_ip(buf);

    // icmp payload
    memcpy(((char *)icmp_hdr_pkt) + ICMP_HEADER_LEN, ip_hdr, IP_HEADER_LEN + ICMP_HEADER_LEN);

    // icmp header
    icmp_hdr_pkt->type = ICMP_TYPE_TIME_EXCEEDED;
    icmp_hdr_pkt->code = 0;
    icmp_hdr_pkt->checksum = 0;
    icmp_hdr_pkt->checksum = htons(checksum((uint16_t *) icmp_hdr_pkt, IP_HEADER_LEN + 2 * ICMP_HEADER_LEN));

    // ip payload
    write_defaults_iphdr(ip_hdr_pkt);
    ip_hdr_pkt->tot_len = htons(2 * IP_HEADER_LEN + 2 * ICMP_HEADER_LEN);
    ip_hdr_pkt->protocol = IPPROTO_ICMP;
    ip_hdr_pkt->saddr = get_interface_ip_uint32(interface);
    ip_hdr_pkt->daddr = ip_hdr->saddr;
    ip_hdr_pkt->check = 0;
    ip_hdr_pkt->check = htons(checksum((uint16_t *) ip_hdr_pkt, ntohs(ip_hdr_pkt->tot_len)));

    // eth header
    eth_hdr_pkt->ether_type = htons(ETHERTYPE_IP);
    memcpy(eth_hdr_pkt->ether_shost, eth_hdr->ether_dhost, 6);
    memcpy(eth_hdr_pkt->ether_dhost, eth_hdr->ether_shost, 6);

    return packet;
}


