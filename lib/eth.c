#include "eth.h"

struct ether_header* hdr_eth(char *buf) {
    return (struct ether_header *) buf;
}

void print_mac(uint8_t *mac) {
	for (int i = 0; i < 6; i++) {
		printf("%02X", mac[i]);
		if (i < 5) {
			printf(":");
		}
	}
	printf("\n");
}

int is_mac_broadcast(uint8_t *mac) {
	for (int i = 0; i < 6; i++) {
		if (mac[i] != 0xFF) {
			return 0;
		}
	}
	return 1;
}
int is_mac_interfaces(uint8_t *mac, int interface) {
	uint8_t my_mac[6];
	get_interface_mac(interface, my_mac);
	for (int i = 0; i < 6; i++) {
		if (mac[i] != my_mac[i]) {
			return 0;
		}
	}
	return 1;
}
int is_packet_destined_to_interface(char *buf, int interface) {
	struct ether_header *eth_hdr = hdr_eth(buf);
	uint8_t *mac = eth_hdr->ether_dhost;
	if (is_mac_broadcast(mac) || is_mac_interfaces(mac, interface)) {
		return 1;
	}
	return 0;
}