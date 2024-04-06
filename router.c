
#include "lib.h"
#include "protocols.h"
#include "routes.h"
#include "eth.h"
#include "arp.h"
#include "icmp.h"
#include "ip.h"

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <linux/if_ether.h>
#include <time.h>

#define MAX_ROUTES 80000
#define MAX_ARP_TABLE_LEN 100

struct route_table_entry routes[MAX_ROUTES];
struct arp_table_entry arp_table[MAX_ARP_TABLE_LEN];

int routes_len = 0;
int arp_table_len = 0;



int mask_len(uint32_t mask) {
	int len = 0;
	while (mask) {
		len += mask & 1;
		mask >>= 1;
	}
	return len;
}

void recv_all(int interface, char *buf, size_t len);

struct iphdr* hdr_ip(char *buf);
struct arp_header* hdr_arp(char *buf);
struct icmphdr* hdr_icmp(char *buf);
void handle_eth(char *buf, int interface);
void handle_arp(char *buf, int interface);
void handle_ip(char* buf, int interface);
void handle_icmp(char *buf, int interface);
void handle_ip_forwarding(char *buf, int interface);
void send_arp_reply(char *buf, int interface);
void send_icmp_reply(char *buf, int interface);

uint32_t get_interface_ip_uint32(int interface) {
	return inet_addr(get_interface_ip(interface));
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


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	routes_len = read_rtable(argv[1], routes);
	
	sort_routes(routes, routes_len);

	for (int i = 0; i < 0; i++) {
		struct in_addr prefix, next_hop, mask;
		prefix.s_addr = routes[i].prefix;
		next_hop.s_addr = routes[i].next_hop;
		mask.s_addr = routes[i].mask;

		char *prefix_str = strdup(inet_ntoa(prefix));
		char *next_hop_str = strdup(inet_ntoa(next_hop));
		char *mask_str = strdup(inet_ntoa(mask));

		printf("%s %s %s %d\n", prefix_str, next_hop_str, mask_str, routes[i].interface);
	}

	return 0;

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		// 	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
		// }


	}
}

void recv_all(int interface, char *buf, size_t len) {
	interface = recv_from_any_link(buf, &len);
	DIE(interface < 0, "recv_from_any_links");
}

void handle_eth(char *buf, size_t len, int interface) {
    struct ether_header *eth_hdr = hdr_eth(buf);

    if (eth_hdr->ether_type == ETHERTYPE_IP) {
        handle_ip(buf, len, interface);
    }
    if (eth_hdr->ether_type == ETHERTYPE_ARP) {
        handle_arp(buf, len, interface);
    }

}

void handle_arp(char *buf, size_t len, int interface) {
    struct arp_header *arp_hdr = hdr_arp(buf);

    if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
        send_arp_reply(buf, len, interface);
    }
}

void handle_ip(char* buf, size_t len, int interface) {
    struct iphdr *ip_hdr = hdr_ip(buf);

    if (ip_hdr->protocol == IPPROTO_ICMP) {
        handle_icmp(buf, len, interface);
        return;
    }
    handle_ip_forwarding(buf, len, interface);
}
void handle_ip_forwarding(char *buf, size_t len, int interface) {
    struct ether_header *eth_hdr = hdr_eth(buf);
    struct iphdr *ip_hdr = hdr_ip(buf);

    if (ip_hdr->daddr == get_interface_ip_uint32(interface)) {
        return; // drop packet, reply for icmp only
    }
    int check = ip_hdr->check;
    ip_hdr->check = 0;

    if (check != checksum((uint16_t *) ip_hdr, sizeof(struct iphdr))) {
        return; // drop packet, invalid checksum
    }
    if (ip_hdr->ttl <= 1) {
        return; // drop packet, ttl expired
    }
    ip_hdr->ttl--;
    ip_hdr->check = checksum((uint16_t *) ip_hdr, sizeof(struct iphdr));

    struct route_table_entry* route = lookup_route(routes, MAX_ROUTES, ip_hdr->daddr);
	if (route == NULL) {
		return; // drop packet, no route
	}

	// place route interface mac in header
	get_interface_mac(route->interface, eth_hdr->ether_shost);

	// find in arp table next hop mac
	struct arp_table_entry *arp_entry = lookup_arp_table(arp_table, arp_table_len, route->next_hop);

	if (arp_entry == NULL) {
		// save packet and send arp request
		return;
	
	}
	// place next hop mac in header
	memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);

	send_to_link(route->interface, buf, len);
}
void send_arp_reply(char *buf, size_t len, int interface) {
	struct ether_header *eth_hdr = hdr_eth(buf);
	struct arp_header *arp_hdr = hdr_arp(buf);

	char *packet = make_arp_reply(arp_hdr->sha, arp_hdr->spa, get_interface_mac(interface), get_interface_ip_uint32(interface));
	send_to_link(interface, packet, ETHER_HEADER_LEN + ARP_HEADER_LEN);

	free(packet);
}

void handle_icmp(char *buf, size_t len, int interface) {
	struct icmphdr *icmp_hdr = hdr_icmp(buf);
	struct iphdr *ip_hdr = hdr_ip(buf);
	struct ether_header *eth_hdr = hdr_eth(buf);

}

