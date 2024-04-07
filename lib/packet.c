#include "packet.h"

packet_t *make_packet(char *data, size_t len, uint32_t interface, uint32_t ip) {
    packet_t *packet = malloc(sizeof(packet_t));
    packet->data = data;
    packet->len = len;
    packet->interface = interface;
    packet->ip = ip;
    return packet;
}
void free_packet(packet_t *packet) {
    free(packet->data);
    free(packet);
}
packet_list_t * make_packet_list() {
    packet_list_t *list = malloc(sizeof(packet_list_t));
    list->head = NULL;
    return list;
}
int is_empty(packet_list_t *list) {
    return list->head == NULL;
}
void add_packet(packet_list_t *list, packet_t *packet) {
    if (list->head == NULL) {
        list->head = malloc(sizeof(node_t));
        list->head->packet = packet;
        list->head->next = NULL;
    } else {
        node_t *current = list->head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = malloc(sizeof(node_t));
        current->next->packet = packet;
        current->next->next = NULL;
    }
}

void free_packet_list(packet_list_t *list) {
    node_t *current = list->head;
    while (current != NULL) {
        node_t *next = current->next;
        free_packet(current->packet);
        free(current);
        current = next;
    }
    free(list);
}