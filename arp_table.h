#ifndef ARP_H
#define ARP_H

#include "skel.h"
#include <stdlib.h>
#include <stdint.h>

typedef struct arp_entry_T {
    uint32_t ip;
    uint8_t mac[ETH_ALEN];
}arp_entry;

typedef struct arp_table_T {
    arp_entry *table;
    int size;
    int max_size;
}arp_table;

arp_table *init_table();
void add_arp_entry(arp_table *table, uint32_t ip, uint8_t mac[ETH_ALEN]);
uint8_t *get_arp_mac(arp_table *table, uint32_t ip);
void free_table(arp_table *table);

#endif /* ARP_H */
