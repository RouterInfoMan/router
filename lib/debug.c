#include "debug.h"

void print_debug_eth_hdr(struct ether_header *eth_hdr)
{
    printf("|-----------------ETHERNET HEADER-----------------|\n");
    printf("Source MAC:      ");
	print_mac(eth_hdr->ether_shost);
	printf("Destination MAC: ");
	print_mac(eth_hdr->ether_dhost);
    printf("Ethertype: ");
    switch (ntohs(eth_hdr->ether_type)) {
        case ETHERTYPE_IP:
            printf("ETHERTYPE_IP\n");
            break;
        case ETHERTYPE_ARP:
            printf("ETHERTYPE_ARP\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }	
}
void print_debug_arp_hdr(struct arp_header* arp_hdr)
{
    printf("|-------------------ARP HEADER--------------------|\n");
    printf("Hardware type: ");
    switch(ntohs(arp_hdr->htype)) {
        case ARP_HTYPE_ETHERNET:
            printf("Ethernet\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("Protocol type: ");
    switch(ntohs(arp_hdr->ptype)) {
        case ETHERTYPE_IP:
            printf("IP\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("Hardware size: %d\n", arp_hdr->hlen);
    printf("Protocol size: %d\n", arp_hdr->plen);
    printf("Opcode: ");
    switch(ntohs(arp_hdr->op)) {
        case ARPOP_REQUEST:
            printf("ARP REQUEST\n");
            break;
        case ARPOP_REPLY:
            printf("ARP REPLY\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("Sender MAC: ");
    print_mac(arp_hdr->sha);
    printf("Sender IP:  ");
    print_ip(ntohl(arp_hdr->spa));
    printf("Target MAC: ");
    print_mac(arp_hdr->tha);
    printf("Target IP:  ");
    print_ip(ntohl(arp_hdr->tpa));
}
void print_debug_ip_hdr(struct iphdr *ip_hdr)
{
    printf("|-------------------IP HEADER---------------------|\n");
    printf("Version: %d\n", ip_hdr->version);
    printf("IHL: %d\n", ip_hdr->ihl);
    printf("Type of Service: %d\n", ip_hdr->tos);
    printf("Total Length: %d\n", ntohs(ip_hdr->tot_len));
    printf("Identification: %d\n", ntohs(ip_hdr->id));
    printf("Fragment Offset: %d\n", ntohs(ip_hdr->frag_off));
    printf("TTL: %d\n", ip_hdr->ttl);
    printf("Protocol: ");
    switch(ip_hdr->protocol) {
        case IPPROTO_ICMP:
            printf("ICMP\n");
            break;
        case IPPROTO_TCP:
            printf("TCP\n");
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("Checksum: 0x%04x\n", ntohs(ip_hdr->check));
    printf("Source IP:      ");
    print_ip(ntohl(ip_hdr->saddr));
    printf("Destination IP: ");
    print_ip(ntohl(ip_hdr->daddr));
}
void print_debug_icmp_hdr(struct icmphdr *icmp_hdr)
{
    printf("|-------------------ICMP HEADER-------------------|\n");
    printf("Type: ");
    switch(icmp_hdr->type) {
        case ICMP_TYPE_ECHO_REPLY:
            printf("ICMP Echo Reply\n");
            break;
        case ICMP_TYPE_DEST_UNREACH:
            printf("ICMP Destination Unreachable\n");
            break;
        case ICMP_TYPE_ECHO_REQUEST:
            printf("ICMP Echo Request\n");
            break;
        case ICMP_TYPE_TIME_EXCEEDED:
            printf("ICMP Time Exceeded\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("Code: %d\n", icmp_hdr->code);
    printf("Checksum: 0x%04x\n", ntohs(icmp_hdr->checksum));
}