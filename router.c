#include "skel.h"
#include "trie.h"
#include "queue.h"
#include "arp_table.h"

#define BROADCAST_MAC "ff:ff:ff:ff:ff:ff"

// Helper function
uint32_t get_ip(int interface) {
    return inet_addr(get_interface_ip(interface));
}

// Recalculate checksum with RFC1624 incremental algorithm
// https://tools.ietf.org/html/rfc1624#section-5
void RFC1624_checksum(struct iphdr *ip_hdr) {
    ip_hdr->check = ip_hdr->check - ~ip_hdr->ttl - ip_hdr->ttl;
    ip_hdr->ttl--;
}

// Send broadcast arp request
void send_arp_request(table_entry *best_entry) {
    struct ether_header eth_hdr;
    uint8_t broadcast_mac[ETH_ALEN];
    
    get_interface_mac(best_entry->interface, eth_hdr.ether_shost);
    hwaddr_aton(BROADCAST_MAC, broadcast_mac);
    memcpy(eth_hdr.ether_dhost, broadcast_mac, sizeof(uint8_t) * ETH_ALEN);
    eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    send_arp(best_entry->next_hop, get_ip(best_entry->interface),
             &eth_hdr, best_entry->interface, htons(ARPOP_REQUEST));
}

// Process normal packets
void process_non_arp(packet *m, trie *trie_rtable, arp_table *table,
                     queue queued_packets) {
    struct ether_header *eth_hdr = (struct ether_header *) m->payload;
    struct iphdr *ip_hdr = parse_ip(m->payload);
    struct icmphdr *icmp_hdr = parse_icmp(m->payload);

    // 2. if icmp echo packet for an address of this router
    // reply with echoreply
    if(icmp_hdr != NULL && icmp_hdr->type == ICMP_ECHO &&
       ip_hdr->daddr == get_ip(m->interface)) {
        send_icmp(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_dhost, 
                  eth_hdr->ether_shost, ICMP_ECHOREPLY, 0, m->interface,
                  ip_hdr->id, icmp_hdr->un.echo.sequence);
        return;
    }

    // 6. if checksum is wrong drop packet
    if(ip_checksum(ip_hdr, sizeof(struct iphdr))) {
        return;
    }

    // 5. if ttl <= 1 then send icmp time exceeded message and drop packet
    if(ip_hdr->ttl <= 1) {
        if(icmp_hdr == NULL) {
            send_icmp_error(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_dhost,
                            eth_hdr->ether_shost, ICMP_TIME_EXCEEDED, 0,
                            m->interface);
        }
        return;
    }

    // 8. search best entry in routing table (implemented with trie)
    // if no entry was found drop packet and send icmp unreach error
    table_entry *best_entry = search_trie(trie_rtable, ip_hdr->daddr);    
    if(best_entry == NULL) {
        send_icmp_error(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_dhost,
                        eth_hdr->ether_shost, ICMP_PORT_UNREACH, 0,
                        m->interface);
        return;
    }

    // 7. decrement ttl and update checksum (with bonus)
    RFC1624_checksum(ip_hdr);

    // 9. modify eth shost and dhost, if the dhost is not in
    // the arp table, send an arp request and save the packet
    // in the queue until a response is recieved. 
    uint8_t *dhost = get_arp_mac(table, best_entry->next_hop);
    if(dhost == NULL) {
        send_arp_request(best_entry);
        
        packet *pack = (packet *) malloc(sizeof(packet));
        memcpy(pack, m, sizeof(packet));
        queue_enq(queued_packets, pack);
        return;
    }

    get_interface_mac(best_entry->interface, eth_hdr->ether_shost);
    memcpy(eth_hdr->ether_dhost, dhost, sizeof(uint8_t) * ETH_ALEN);

    // 10. send the packet to the next hop.
    send_packet(best_entry->interface, m);
}

// respond to an arp request with an arp reply
void respond_arp_request(packet *m) {
    struct ether_header *eth_hdr = (struct ether_header*)m->payload;
    struct arp_header *arp_hdr = parse_arp(m->payload);
    struct ether_header req_eth;

    if(arp_hdr->tpa == get_ip(m->interface)) {
        memcpy(req_eth.ether_dhost, eth_hdr->ether_shost,
               sizeof(uint8_t) * ETH_ALEN);
        get_interface_mac(m->interface, req_eth.ether_shost);
        req_eth.ether_type = htons(ETHERTYPE_ARP);

        send_arp(arp_hdr->spa, arp_hdr->tpa, &req_eth, m->interface,
                 htons(ARPOP_REPLY));
    }
}

// add arp response to arp table and process all packets dependent on it
void process_arp_response(packet *m, arp_table *table, queue queued_packets,
                          trie *trie_rtable) {
    struct arp_header *arp_hdr = parse_arp(m->payload);
    struct iphdr *ip_hdr = parse_ip(m->payload);
    add_arp_entry(table, arp_hdr->spa, arp_hdr->sha);
    
    while (!queue_empty(queued_packets)) {
        packet *pack = (packet *)queue_deq(queued_packets);

        ip_hdr = parse_ip(pack->payload);

        table_entry *best_entry = search_trie(trie_rtable, ip_hdr->daddr);

        DIE (best_entry == NULL, "Dest Unerach for ARP packet");

        if (arp_hdr->spa == best_entry->next_hop) {
            process_non_arp(pack, trie_rtable, table, queued_packets);
            free(pack);
        } else {
            queue_enq(queued_packets, pack);
            break;
        }
    }

}

int main(int argc, char *argv[])
{
    // init routing table as trie for fast search
    trie *trie_rtable = parse_rtable(argv[1]);
    // init arp table, initally empty
    arp_table *table = init_table();
    // init packet queue, initially empty
    queue queued_packets = queue_create();
    packet m;
    int rc;

    init(argc - 2, argv + 2);
    DIE(trie_rtable == NULL, "parse_rtable");

    while (1) {
        // 1. read incoming packet on any interface
        rc = get_packet(&m);
        DIE(rc < 0, "get_message");

        struct arp_header *arp_hdr = parse_arp(m.payload);
        if(arp_hdr != NULL) {           
            if(ntohs(arp_hdr->op) == ARPOP_REQUEST) {
                // 3. respond to arp request
                respond_arp_request(&m);
            } else if(ntohs(arp_hdr->op) == ARPOP_REPLY) {
                // 4. add arp response to table and respond dependent packets
                process_arp_response(&m, table, queued_packets, trie_rtable);
            }
        } else {
            // steps 2 & 5-10
            process_non_arp(&m, trie_rtable, table, queued_packets);
        }
    }

    // Unreachable but here for flex.
    free_table(table);
    free_trie(trie_rtable);
    while(!queue_empty(queued_packets)) {
        free(queue_deq(queued_packets));
    }
    free(queued_packets);

    return 0;
}
