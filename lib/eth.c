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