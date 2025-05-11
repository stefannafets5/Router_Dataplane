#include "protocols.h"
#include "queue.h"
#include "list.h"
#include "lib.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>

typedef struct trie_node {
	struct trie_node *zero;
	struct trie_node *one;
	struct route_table_entry *entry;
} trie_node;

struct pending_packet {
	char *buf;
	size_t len;
	int interface;
	uint32_t next_hop;
};

#define MAX_RTABLE_LEN 100000
#define MAX_ARP_LEN 100000
#define ARP_REQUEST 1
#define ARP_REPLY 2

struct route_table_entry *rtable;
int rtable_size = 0;

struct arp_table_entry *arp_table;
int arp_table_len = 0;

void swap(uint32_t *a, uint32_t *b) {
	int temp = *a;
	*a = *b;
	*b = temp;
}

// find ip in arp table
struct arp_table_entry *get_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

trie_node *insert_route(trie_node *root, struct route_table_entry *entry) {
	if (!root)
		root = calloc(1, sizeof(trie_node));

	trie_node *node = root;
	uint32_t prefix = ntohl(entry->prefix);
	uint32_t mask = ntohl(entry->mask);
	
	for (int i = 31; i >= 0; i--) {
		if (!(mask & (1 << i))) {
			break;
		}
		int bit = (prefix >> i) & 1;
		if (bit == 0) {
			if (!node->zero) {
				node->zero = calloc(1, sizeof(trie_node));
			}
			node = node->zero;
		} else {
			if (!node->one) {
				node->one = calloc(1, sizeof(trie_node));
			}
			node = node->one;
		}
	}
	node->entry = entry;
	return root;
}

void initialize_structs(const char *rtable_path, trie_node **trie) {
	rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_LEN);
	DIE(rtable == NULL, "no memory for route table");
	rtable_size = read_rtable(rtable_path, rtable);

	arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP_LEN);
	DIE(arp_table == NULL, "no memory for ARP table");

	for (int i = 0; i < rtable_size; i++) {
		*trie = insert_route(*trie, &rtable[i]);
	}
}

struct route_table_entry *trie_lookup(trie_node *root, uint32_t ip) {
	struct route_table_entry *best_match = NULL;
	trie_node *node = root;

	for (int i = 31; i >= 0 && node; i--) {
		if (node->entry) {
			best_match = node->entry;
		}

		int bit = (ntohl(ip) >> i) & 1;
		if (bit == 0) {
			node = node->zero;
		} else {
			node = node->one;
		}
	}

	if (node && node->entry){
		best_match = node->entry;
	}
	return best_match;
}

void free_trie(trie_node *node) {
	if (!node) return;
	free_trie(node->zero);
	free_trie(node->one);
	free(node);
}

void fill_headers (struct ip_hdr *ip_new, struct icmp_hdr *icmp_hdr, int m_type, int m_code, char buff[], struct ip_hdr *ip_hdr) {
	// fill icmp header
	icmp_hdr->mtype = m_type;
	icmp_hdr->mcode = m_code;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr)));
	
	memcpy(icmp_hdr + sizeof(*icmp_hdr), ip_hdr, sizeof(*ip_hdr));
	memcpy(icmp_hdr + sizeof(*icmp_hdr) + sizeof(*ip_hdr), buff + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), 8);

	// fill ip header
	ip_new->ihl = 5;
	ip_new->ver = 4;
	ip_new->tos = 0;
	ip_new->tot_len = htons(sizeof(*ip_hdr) + sizeof(*icmp_hdr));
	ip_new->id = 1;
	ip_new->frag = 0;
	ip_new->ttl = 64;
	ip_new->proto = 1;
	ip_new->checksum = htons(checksum((uint16_t *)ip_new, sizeof(*ip_hdr)));
}

void fill_ether_header(struct ether_hdr *eth_new, struct ether_hdr *eth_old, int interface) {
	memcpy(eth_new->ethr_dhost, eth_old->ethr_shost, 6);
	get_interface_mac(interface, eth_old->ethr_shost);
	eth_new->ethr_type = htons(0x0800);
}

void send_arp_request(uint32_t target_ip, int interface) {
	char buf[MAX_PACKET_LEN];
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

	// ethernet header
	memset(eth_hdr->ethr_dhost, 0xFF, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);
	eth_hdr->ethr_type = htons(0x0806);

	// ARP header
	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(0x0800);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(ARP_REQUEST);
	get_interface_mac(interface, arp_hdr->shwa);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
	memset(arp_hdr->thwa, 0, 6);
	arp_hdr->tprotoa = target_ip;

	size_t len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	send_to_link(len, buf, interface);
}

void process_arp_reply(struct arp_hdr *arp_hdr, queue pending_packets, int interface) {
	// add to ARP cache
	if (arp_table_len < MAX_ARP_LEN) {
		arp_table[arp_table_len].ip = arp_hdr->sprotoa;
		memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, 6);
		arp_table_len++;
	}

	// process pending packets
	queue temp = create_queue();
	while (!queue_empty(pending_packets)) {
		struct pending_packet *pp = queue_deq(pending_packets);
		if (pp->next_hop == arp_hdr->sprotoa) {
			struct ether_hdr *eth_hdr = (struct ether_hdr *)pp->buf;
			memcpy(eth_hdr->ethr_dhost, arp_hdr->shwa, 6);
			get_interface_mac(pp->interface, eth_hdr->ethr_shost);
			send_to_link(pp->len, pp->buf, pp->interface);
			free(pp->buf);
			free(pp);
		} else {
			queue_enq(temp, pp);
		}
	}

	// restore unprocessed packets
	while (!queue_empty(temp)) {
		queue_enq(pending_packets, queue_deq(temp));
	}
	free(temp);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	init(argv + 2, argc - 2);

	trie_node *trie = NULL;
	initialize_structs(argv[1], &trie);

	queue pending_packets = create_queue();

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		if (len < sizeof(struct ether_hdr)) {
			// ignore
			continue;
		}

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		if (ntohs(eth_hdr->ethr_type) == 0x0806) {
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			if (ntohs(arp_hdr->opcode) == ARP_REPLY) {
				process_arp_reply(arp_hdr, pending_packets, interface);
			} else if (ntohs(arp_hdr->opcode) == ARP_REQUEST) {
				// Check if the request is for this interface
				if (arp_hdr->tprotoa == inet_addr(get_interface_ip(interface))) {
					// send ARP
					char reply_buf[MAX_PACKET_LEN];
					struct ether_hdr *reply_eth = (struct ether_hdr *)reply_buf;
					struct arp_hdr *reply_arp = (struct arp_hdr *)(reply_buf + sizeof(struct ether_hdr));

					// fill ethernet
					memcpy(reply_eth->ethr_dhost, arp_hdr->shwa, 6);
					get_interface_mac(interface, reply_eth->ethr_shost);
					reply_eth->ethr_type = htons(0x0806);

					// fill ARP header
					reply_arp->hw_type = htons(1);
					reply_arp->proto_type = htons(0x0800);
					reply_arp->hw_len = 6;
					reply_arp->proto_len = 4;
					reply_arp->opcode = htons(ARP_REPLY);
					get_interface_mac(interface, reply_arp->shwa);
					reply_arp->sprotoa = arp_hdr->tprotoa;
					memcpy(reply_arp->thwa, arp_hdr->shwa, 6);
					reply_arp->tprotoa = arp_hdr->sprotoa;

					// send
					size_t reply_len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
					send_to_link(reply_len, reply_buf, interface);
				}
			}
			continue;

		} else if (ntohs(eth_hdr->ethr_type) == 0x0800) {
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

			// verify if mac adress is mine or broadcast
			uint8_t interface_mac[6];
			get_interface_mac(interface, interface_mac);
			
			int for_me = memcmp(eth_hdr->ethr_dhost, interface_mac, 6) == 0;
			int is_broadcast = memcmp(eth_hdr->ethr_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0;

			if (!for_me && !is_broadcast) {
				// ignore (not for me)
				continue;
			}

			if (inet_addr(get_interface_ip(interface)) == ip_hdr->dest_addr) {
				// router is destination
				char buf2[MAX_PACKET_LEN];
			
				// fill ethernet
				struct ether_hdr *eth_new = (struct ether_hdr *)buf2;
				fill_ether_header(eth_new, eth_hdr, interface);

				// fill the headers
				struct ip_hdr *ip_new = (struct ip_hdr *)(buf2 + sizeof(struct ether_hdr));
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf2 + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				swap(&ip_hdr->source_addr, &ip_hdr->dest_addr);
				fill_headers(ip_new, icmp_hdr, 0, 0, buf, ip_hdr);

				// send
				send_to_link(sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8, buf2, interface);
				continue;
			}

			uint16_t old_sum = ntohs(ip_hdr->checksum);
			ip_hdr->checksum = 0;
			if (old_sum != checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr))) {
				// ignore (checksum not matching)
				continue;
			}

			if (ip_hdr->ttl < 2) {
				// TTL < 2, send ICMP
				char buf2[MAX_PACKET_LEN];
			
				// fill ethernet
				struct ether_hdr *eth_new = (struct ether_hdr *)buf2;
				fill_ether_header(eth_new, eth_hdr, interface);

				// fill the headers
				struct ip_hdr *ip_new = (struct ip_hdr *)(buf2 + sizeof(struct ether_hdr));
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf2 + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				swap(&ip_hdr->source_addr, &ip_hdr->dest_addr);
				fill_headers(ip_new, icmp_hdr, 11, 0, buf, ip_hdr);

				// send
				send_to_link(sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8, buf2, interface);
				continue;
			}
			ip_hdr->ttl --;

			struct route_table_entry *best_route = trie_lookup(trie, ip_hdr->dest_addr);
			if (!best_route) {
				// no best route
				char buf2[MAX_PACKET_LEN];
			
				// fill ethernet
				struct ether_hdr *eth_new = (struct ether_hdr *)buf2;
				fill_ether_header(eth_new, eth_hdr, interface);

				// fill the headers
				struct ip_hdr *ip_new = (struct ip_hdr *)(buf2 + sizeof(struct ether_hdr));
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf2 + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				swap(&ip_hdr->source_addr, &ip_hdr->dest_addr);
				fill_headers(ip_new, icmp_hdr, 3, 0, buf, ip_hdr);

				// send
				send_to_link(sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8, buf2, interface);
				continue;
			}

			ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

			struct arp_table_entry *entry_arp  = get_arp_entry(best_route->next_hop);
			if(entry_arp == NULL){
				// qeue packet
				struct pending_packet *pp = malloc(sizeof(struct pending_packet));
				pp->buf = malloc(len);
				memcpy(pp->buf, buf, len);
				pp->len = len;
				pp->interface = best_route->interface;
				pp->next_hop = best_route->next_hop;
				queue_enq(pending_packets, pp);

				// arp request
				send_arp_request(best_route->next_hop, best_route->interface);
				continue;
			} else {
				memcpy(eth_hdr->ethr_dhost, entry_arp->mac, 6);
				get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
				send_to_link(len, buf, best_route->interface);
			}
		}
	}
	free(rtable);
	free(arp_table);
	free_trie(trie);
	while (!queue_empty(pending_packets)) {
		struct pending_packet *pp = queue_deq(pending_packets);
		free(pp->buf);
		free(pp);
	}
	free(pending_packets);
}