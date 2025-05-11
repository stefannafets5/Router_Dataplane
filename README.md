#Copyright - Springer Robert Stefan 2025

- In main, the program receives Ethernet frames via "recv_from_any_link" and
processes them based on type (IP or ARP). It uses a trie for routing and a
dynamic ARP table to forward packets or send ICMP replies. If an ARP entry is
missing, the packet is queued and an ARP request is sent.

- Forwarding: If the MAC address is known, the packet is forwarded after
updating the Ethernet header.

- A trie organizes routes for fast lookups using "trie_lookup". Each node
leads to a "route_table_entry" with the best prefix match.

- The "arp_table" stores IP-to-MAC mappings, built dynamically from ARP replies.
"get_arp_entry" retrieves an entry by IP.

- The "pending_packet" structure holds packets waiting for ARP resolution.
The "pending_packets" queue keeps them until MAC addresses are known.

- "fill_ether_header": sets the Ethernet header for ICMP replies using the
source MAC and the router's MAC.

- "fill_headers": fills in IP and ICMP headers for the reply.

- "send_arp_request": sends an ARP request for a given IP address.

- "process_arp_reply": updates the ARP table and sends queued packets.

    Utility functions:

- "initialize_structs": loads the routing table and initializes the trie and
an empty ARP table.

- "free_trie": recursively frees the trie at the end.