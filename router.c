
#include "lib.h"
#include "protocols.h"
#include "routes.h"
#include "eth.h"
#include "arp.h"
#include "icmp.h"
#include "ip.h"
#include "packet.h"
#include "lpm_trie.h"
#include "debug.h"

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <linux/if_ether.h>
#include <time.h>

#define MAX_ROUTES 80000
#define MAX_ARP_TABLE_LEN 100

struct route_table_entry routes[MAX_ROUTES];
struct arp_table_entry arp_table[MAX_ARP_TABLE_LEN];
packet_list_t *packet_list;
lpm_trie_t *trie;

int routes_len = 0;
int arp_table_len = 0;



int8_t mask_len(uint32_t mask)
{
	int8_t len = 0;
	while (mask) {
		len += mask & 1;
		mask >>= 1;
	}
	return len;
}

void handle_eth(char *buf, size_t len, int interface);
void handle_arp(char *buf, size_t len, int interface);
void handle_ip(char* buf, size_t len, int interface);
void handle_icmp(char *buf, size_t len, int interface, int res);
int  handle_ip_forwarding(char *buf, size_t len, int interface);
void handle_ip_fwd_err(char *buf, size_t len, int interface, int res);
void handle_arp_reply(char *buf, size_t len, int interface);
void handle_arp_request(char *buf, size_t len, int interface);
void dequeue_packets();


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	routes_len = read_rtable(argv[1], routes);
	// sort_routes(routes, routes_len);

	trie = lpm_trie_create();
	for (int i = 0; i < routes_len; i++) {
		lpm_trie_insert(trie, ntohl(routes[i].prefix), mask_len(routes[i].mask), routes[i].next_hop, routes[i].interface);
	}
	packet_list = make_packet_list();

	// return 0;

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

		handle_eth(buf, len, interface);

		dequeue_packets();

	}
}

void dequeue_packets()
{
	printf("|-------------HANDLING QUEUED PACKETS-------------|\n");
	if (is_empty(packet_list)) {
		printf("No packets to dequeue\n");
		return;
	}

	printf("ARP table len: %d\n", arp_table_len);
	node_t *current = packet_list->head;

    while (current != NULL) {
        packet_t *packet = current->packet;
        struct arp_table_entry *entry = lookup_arp_table(arp_table, arp_table_len, packet->ip);
        if (entry == NULL) {
            current = current->next;
            continue;
        }
		struct ether_header *eth_hdr = hdr_eth(packet->data);
		struct iphdr *ip_hdr = hdr_ip(packet->data);
        memcpy(eth_hdr->ether_dhost, entry->mac, 6);
		printf("|------------------SENDING PACKET-----------------|\n");
		printf("Destination MAC: ");
		print_mac(eth_hdr->ether_dhost);
		printf("Source MAC:      ");
		print_mac(eth_hdr->ether_shost);
		printf("Destination IP:  ");
		print_ip(ntohl(ip_hdr->daddr));
		printf("Source IP:       ");
		print_ip(ntohl(ip_hdr->saddr));

        send_to_link(packet->interface, packet->data, packet->len);

        node_t *next = current->next;
        if (current == packet_list->head) {
            packet_list->head = current->next;
        }

        free_packet(current->packet);
        free(current);
        current = next;
    }
}

void handle_eth(char *buf, size_t len, int interface)
{
	struct ether_header *eth_hdr = hdr_eth(buf);

	printf("\nReceived packet from interface %d\n", interface);
	print_debug_eth_hdr(eth_hdr);

	if (!is_packet_destined_to_interface(buf, interface)) {
		printf("Packet not for this interface\n");
		return;
	}
	
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		handle_ip(buf, len, interface);
	}
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
		handle_arp(buf, len, interface);
	}
}

void handle_arp(char *buf, size_t len, int interface)
{
    struct arp_header *arp_hdr = hdr_arp(buf);
	
	print_debug_arp_hdr(arp_hdr);
    if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
        handle_arp_request(buf, len, interface);
    }
	if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
		handle_arp_reply(buf, len, interface);
	}
}
void handle_arp_reply(char *buf, size_t len, int interface)
{
	struct arp_header *arp_hdr = hdr_arp(buf);
	
	printf("|-----------------HANDLING REPLY------------------|\n");
	printf("Adding new entry/updating entry\n");
	add_new_entry(arp_table, &arp_table_len, arp_hdr->spa, arp_hdr->sha);
}
void handle_arp_request(char *buf, size_t len, int interface)
{
	struct arp_header *arp_hdr = hdr_arp(buf);
	
	uint8_t if_mac[6];
	get_interface_mac(interface, if_mac);

	printf("|-----------------HANDLING REQUEST----------------|\n");
	uint32_t if_ip = get_interface_ip_uint32(interface);
	if (arp_hdr->tpa != if_ip) {
		printf("ARP request not for this interface\n");
		return;
	}

	printf("Sending ARP reply\n");
	char *packet = make_arp_reply(arp_hdr->sha, arp_hdr->spa, if_mac, if_ip);
	send_to_link(interface, packet, ETHER_HEADER_LEN + ARP_HEADER_LEN);

	free(packet);
}


void handle_ip(char* buf, size_t len, int interface)
{
    struct iphdr *ip_hdr = hdr_ip(buf);

	print_debug_ip_hdr(ip_hdr);

	char *new_buf = malloc(len);
	memcpy(new_buf, buf, len);

	int res = handle_ip_forwarding(new_buf, len, interface);

	if (ip_hdr->protocol == IPPROTO_ICMP) {
        handle_icmp(buf, len, interface, res);
    }
	if (res != IP_FWD_GOOD && res != IP_FWD_FOR_ROUTER) {
		handle_ip_fwd_err(buf, len, interface, res);
	}

	free(new_buf);
}
int handle_ip_forwarding(char *buf, size_t len, int interface)
{
    struct ether_header *eth_hdr = hdr_eth(buf);
    struct iphdr *ip_hdr = hdr_ip(buf);

	printf("|--------------------ROUTING----------------------|\n");

    if (ip_hdr->ttl <= 1) {
		printf("TTL expired\n");
        return IP_FWD_TIME_EXCEEDED; // drop packet, ttl expired
    }

	if (ip_hdr->daddr == get_interface_ip_uint32(interface)) {
		printf("Packet for router\n");
        return IP_FWD_FOR_ROUTER; // lets decide what to do with it
    }
	uint16_t check = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    if (check != checksum((uint16_t *) ip_hdr, ntohs(ip_hdr->tot_len))) {
		printf("Invalid checksum\n");
        return IP_FWD_BAD_CHECKSUM; // drop packet, invalid checksum
    }

    ip_hdr->ttl--;
    ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, ntohs(ip_hdr->tot_len)));

    uint32_t next_hop;
	int route_interface;

	int route = lookup_route_via_trie(trie, ntohl(ip_hdr->daddr), &next_hop, &route_interface);

	if (route == 0) {
		printf("No route\n");
		return IP_FWD_NO_ROUTE; // drop packet, no route
	}
	printf("Found route\n");
	printf("Next hop: ");
	print_ip(ntohl(next_hop));
	printf("Interface: %d\n", route_interface);

	// place route interface mac in header
	get_interface_mac(route_interface, eth_hdr->ether_shost);

	// find in arp table next hop mac
	struct arp_table_entry *arp_entry = lookup_arp_table(arp_table, arp_table_len, next_hop);
	
	printf("ARP Lookup\n");
	if (arp_entry == NULL) {
		printf("No arp entry\n");
		printf("Sending ARP request\n");
		printf("Target IP:     ");
		print_ip(ntohl(next_hop));
		printf("Interface IP:  ");
		print_ip(ntohl(get_interface_ip_uint32(route_interface)));
		printf("Interface MAC: ");
		print_mac(eth_hdr->ether_shost);
		// save packet and send arp request
		char *arp_req = make_arp_request(next_hop, eth_hdr->ether_shost, get_interface_ip_uint32(route_interface));
		send_to_link(route_interface, arp_req, ETHER_HEADER_LEN + ARP_HEADER_LEN);

		char *new_buf = malloc(len);
		memcpy(new_buf, buf, len);

		printf("Adding packet to queue\n");
		packet_t *packet = make_packet(new_buf, len, route_interface, next_hop);
		add_packet(packet_list, packet);
		return IP_FWD_GOOD;
	}
	printf("Next hop MAC: ");
	print_mac(arp_entry->mac);
	// place next hop mac in header
	memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);

	send_to_link(route_interface, buf, len);

	return IP_FWD_GOOD;
}
void handle_icmp(char *buf, size_t len, int interface, int res)
{
	struct icmphdr *icmp_hdr = hdr_icmp(buf);
	struct iphdr *ip_hdr = hdr_ip(buf);
	struct ether_header *eth_hdr = hdr_eth(buf);

	print_debug_icmp_hdr(icmp_hdr);

	// Echo Reply
	if (res == IP_FWD_FOR_ROUTER && icmp_hdr->type == ICMP_TYPE_ECHO_REQUEST) {
		uint16_t check;

		check = ntohs(ip_hdr->check);
		ip_hdr->check = 0;
		if (check != checksum((uint16_t *) ip_hdr, ntohs(ip_hdr->tot_len))) {
			printf("Invalid checksum IP header\n");
			return;
		}

		check = ntohs(icmp_hdr->checksum);
		icmp_hdr->checksum = 0;
		if (check != checksum((uint16_t *) icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr))) {
			printf("Invalid checksum ICMP header\n");
			return;
		}

		if (ip_hdr->ttl <= 1) {
			printf("TTL expired\n");
			return;
		}

		// swap macs
		char mac[6];
		memcpy(mac, eth_hdr->ether_shost, 6);
		memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
		memcpy(eth_hdr->ether_dhost, mac, 6);

		// swap ips
		ip_hdr->daddr = ip_hdr->saddr;
		ip_hdr->saddr = get_interface_ip_uint32(interface);

		icmp_hdr->type = ICMP_TYPE_ECHO_REPLY;

		icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));

		check = ntohs(ip_hdr->check);
		ip_hdr->ttl--;

		ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, ntohs(ip_hdr->tot_len)));

		send_to_link(interface, buf, len);
	}
}
void handle_ip_fwd_err(char *buf, size_t len, int interface, int res) {
	printf("|---------HANDLING IP FORWARDING ERRORS-----------|\n");

	if (res == IP_FWD_NO_ROUTE) {
		printf("Sending ICMP Destination unreachable\n");

		char *packet = make_dest_unreachable(buf, len, interface);
		send_to_link(interface, packet, ETHER_HEADER_LEN + 2 * IP_HEADER_LEN + 2 * ICMP_HEADER_LEN);
	}
	if (res == IP_FWD_TIME_EXCEEDED) {
		printf("Sending ICMP Time exceeded\n");

		char *packet = make_time_exceeded(buf, len, interface);
		send_to_link(interface, packet, ETHER_HEADER_LEN + 2 * IP_HEADER_LEN + 2 * ICMP_HEADER_LEN);
		free(packet);
	}
}