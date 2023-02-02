#include "trie.h"

trie *init_trie() {
    trie *new_trie = (trie *) malloc(sizeof(trie));
    new_trie->bit0 = NULL;
    new_trie->bit1 = NULL;
    new_trie->size = 0;
    new_trie->addr = NULL;

    return new_trie;
}

void add_trie(trie *root, table_entry *addr) {
    uint32_t mask = addr->mask, preffix = addr->prefix;

    for(int i = 0; i <= 24 && mask; i += 8) {
        for(int j = 7; j >= 0 && mask; j--) {
            int index = i + j;
            mask ^= (1LL << index);
            root->size++;
            if(preffix & (1LL << index)) {
                if(root->bit1 == NULL) {
                    root->bit1 = init_trie();
                }
                root = root->bit1;
            } else {
                if(root->bit0 == NULL) {
                    root->bit0 = init_trie();
                }
                root = root->bit0;
            }

            if(!mask) break;

            index--;
        }
    }
    root->size++;
    root->addr = addr;
}

table_entry *search_trie(trie *root, uint32_t preffix) {
    table_entry *result = NULL;
    //printf("%x\n", preffix);
    for(int i = 0; i <= 24; i += 8) {
        for(int j = 7; j >= 0; j--) {
            if(root->addr != NULL) {
                result = root->addr;
            }
            int index = i + j;
            if(preffix & (1LL << index)) {
                if(root->bit1 == NULL) {
                    return result;
                } else {
                    if(root->addr != NULL) {
                        result = root->addr;
                    }
                    root = root->bit1;
                }
            } else {
                if(root->bit0 == NULL) {
                    return result;
                } else {
                    if(root->addr != NULL) {
                        result = root->addr;
                    }
                    root = root->bit0;
                }
            }
        }
    }
    return result;
}

void free_trie(trie *root) {
    if(root->bit0 != NULL) {
        free_trie(root->bit0);
    }

    if(root->bit1 != NULL) {
        free_trie(root->bit1);
    }

    if(root->addr != NULL)
        free(root->addr);
    free(root);
}

int is_valid_entry(table_entry entry) {
    uint32_t mask = entry.mask;
    for(int i = 0; i <= 24 && mask; i += 8) {
        for(int j = 7; j >= 0 && mask; j--) {
            int index = i + j;
            if((mask & (1LL << index)) == 0) {
                return 0;
            }
            mask ^= (1LL << index);
            if(!mask) break;
        }
    }

    if((entry.prefix & (~entry.mask)) != 0) {
        return 0;
    }
    else {
        return 1;
    }
}

trie *parse_rtable(char *filename) {
    char buff[BUFFER_SIZE];
    char prefix[IP_STR_SIZE], next_hop[IP_STR_SIZE], mask[IP_STR_SIZE];
    trie *trie_table = init_trie();

    FILE *in = fopen(filename, "r");
    if(in == NULL) {
        return NULL;
    }

    trie_table = init_trie();

    while (fgets(buff, sizeof(buff), in) != NULL) {
	table_entry *entry = (table_entry *)malloc(sizeof(table_entry));
        sscanf(buff, "%s %s %s %d", prefix, next_hop, mask, &entry->interface);
        entry->prefix = inet_addr(prefix);
        entry->next_hop = inet_addr(next_hop);
        entry->mask = inet_addr(mask);

        if(is_valid_entry(*entry)) {
            add_trie(trie_table, entry);
        }
    }

    fclose(in);

    return trie_table;
}
