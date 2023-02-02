#ifndef TRIE_H
#define TRIE_H

#include "skel.h"
#include <stdlib.h>
#include <stdint.h>

#define BUFFER_SIZE 256
#define IP_STR_SIZE 16

typedef struct table_entry_T {
    uint32_t prefix;
    uint32_t next_hop;
    uint32_t mask;
    int interface;
} table_entry;

typedef struct trie_T {
    struct trie_T *bit0, *bit1;
    int size;
    table_entry *addr;
} trie;

trie *init_trie();
void add_trie(trie *root, table_entry *addr);
table_entry *search_trie(trie *root, uint32_t preffix);
void free_trie(trie *root);

int is_valid_entry(table_entry entry);
trie *parse_rtable(char *filename);

#endif /* TRIE_H */
