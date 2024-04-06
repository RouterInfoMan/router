extern "C" {
	#include "lib.h"
	#include "protocols.h"
}
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <iostream>

#define MAX_ROUTES 1000000

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

void recv_all(int interface, char *buf, size_t len);
struct ether_header* hdr_eth(char *buf);
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



struct route_table_entry routes[MAX_ROUTES];



int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	read_rtable(argv[1], routes);
	

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
struct route_table_entry* get_best_route(uint32_t dest_ip) {
	struct route_table_entry *best_route = NULL;
	for (int i = 0; i < MAX_ROUTES; i++) {
		if ((dest_ip & routes[i].mask) == (routes[i].prefix & routes[i].mask)) {
			if (best_route == NULL || routes[i].mask > best_route->mask) {
				best_route = &routes[i];
			}
		}
	}
	return best_route;
}

void recv_all(int interface, char *buf, size_t len) {
	interface = recv_from_any_link(buf, &len);
	DIE(interface < 0, "recv_from_any_links");
}
struct ether_header* hdr_eth(char *buf) {
    return (struct ether_header *) buf;
}
struct iphdr* hdr_ip(char *buf) {
    return (struct iphdr *) (buf + sizeof(struct ether_header));
}
struct arp_header* hdr_arp(char *buf) {
    return (struct arp_header *) (buf + sizeof(struct ether_header));
}
struct icmphdr* hdr_icmp(char *buf) {
    return (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
}


void handle_eth(char *buf, int interface) {
    struct ether_header *eth_hdr = hdr_eth(buf);

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        handle_ip(buf, interface);
    }
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        handle_arp(buf, interface);
    }

}

void handle_arp(char *buf, int interface) {
    struct arp_header *arp_hdr = hdr_arp(buf);

    if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
        send_arp_reply(buf, interface);
    }
}

void handle_ip(char* buf, int interface) {
    struct iphdr *ip_hdr = hdr_ip(buf);

    if (ip_hdr->protocol == IPPROTO_ICMP) {
        handle_icmp(buf, interface);
        return;
    }
    handle_ip_forwarding(buf, interface);
}
void handle_ip_forwarding(char *buf, int interface) {
    struct ether_header *eth_hdr = hdr_eth(buf);
    struct iphdr *ip_hdr = hdr_ip(buf);

    if (ntohl(ip_hdr->daddr) == get_interface_ip_uint32(interface)) {
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

    struct route_table_entry* route = get_best_route(ntohl(ip_hdr->daddr));
	if (route == NULL) {
		return; // drop packet, no route
	}

	// place route interface mac in header
	get_interface_mac(route->interface, eth_hdr->ether_shost);
	// find in arp table next hop mac
	

}
void send_arp_reply(char *buf, int interface) {
	struct ether_header *eth_hdr = hdr_eth(buf);
	struct arp_header *arp_hdr = hdr_arp(buf);

}

void handle_icmp(char *buf, int interface) {
	struct icmphdr *icmp_hdr = hdr_icmp(buf);
	struct iphdr *ip_hdr = hdr_ip(buf);
	struct ether_header *eth_hdr = hdr_eth(buf);

}

