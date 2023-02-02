#include "arp_table.h"

arp_table *init_table() {
    arp_table *new_table = (arp_table *)malloc(sizeof(arp_table));

    new_table->size = 0;
    new_table->max_size = 1;
    new_table->table = (arp_entry *)malloc(sizeof(arp_entry));

    return new_table;
}

void add_arp_entry(arp_table *table, uint32_t ip, uint8_t *mac) {
    if(table->size == table->max_size) {
        table->max_size *= 2;
        table->table = (arp_entry *)realloc(table->table, sizeof(arp_entry) * table->max_size);
    }

    table->table[table->size].ip = ip;
    memcpy(table->table[table->size].mac, mac, sizeof(uint8_t) * ETH_ALEN);
    table->size++;

    for(int i = 0; i < table->size; i++) {
        printf("%08x %02x:%02x:%02x:%02x:%02x:%02x\n", table->table[i].ip, table->table[i].mac[0], table->table[i].mac[1], table->table[i].mac[2], table->table[i].mac[3], table->table[i].mac[4], table->table[i].mac[5]);
    }
}

uint8_t *get_arp_mac(arp_table *table, uint32_t ip) {
    for(int i = 0; i < table->size; i++) {
        if(table->table[i].ip == ip) {
            return table->table[i].mac;
        }
    }

    return NULL;
}
void free_table(arp_table *table) {
    free(table->table);
    free(table);
}
