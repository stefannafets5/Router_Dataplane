# ICMP and IPv4 Router Implementation

**Copyright © Springer Robert Stefan, 2025**

## Overview

This project implements the dataplane of an IPv4 router with support for ICMP protocol handling and ARP caching. The router processes incoming IPv4 packets, performs routing decisions using a Longest Prefix Match algorithm, and generates appropriate ICMP messages for error handling and diagnostics.

---

## Features

### IPv4 Packet Forwarding

- Parsing and validation of incoming IPv4 packets (checksum verification, TTL handling)  
- Decrementing TTL and generating ICMP Time Exceeded messages when TTL expires  
- Forwarding packets to the next hop based on the routing table entries

### ICMP Protocol Support

- Generating ICMP Destination Unreachable messages when no route exists to the destination  
- Responding to ICMP Echo Requests with Echo Replies, preserving identifiers and sequence numbers  
- Including original packet headers and payload data in ICMP error messages as per RFC 792

### ARP Protocol with Caching

- Dynamic ARP cache population from received ARP replies  
- Queueing packets awaiting ARP resolution to avoid blocking packet processing  
- Sending ARP requests and handling ARP replies to update the cache

### Efficient Routing Table Lookup

- Implemented Longest Prefix Match using a trie data structure for fast routing decisions  
- Optimized search compared to linear scan, suitable for large routing tables

---

## Technical Details

- All network data is handled in Network Byte Order, with conversions to Host Byte Order for processing  
- Checksums for IPv4 and ICMP headers are computed to ensure packet integrity  
- ICMP error messages include the original IPv4 header plus the first 64 bits of the payload as required  
- Router’s MAC and IP addresses are programmatically retrieved for packet construction

---

## Testing and Debugging

- Used standard `ping` and `ping -t 1` commands to verify ICMP Echo Reply and Time Exceeded messages  
- Tested routing behavior and ICMP error generation with `traceroute`  
- Captured and analyzed packets using Wireshark to verify correct protocol handling and checksum accuracy  
- Used `arping` to test ARP request/reply functionality and cache updates

---

## How to Run

1. Build the project:  
   ```bash
   make
   ```
2. Run the router executable:  
   ```bash
   ./router
   ```
3. Test with ping commands:  
   ```bash
   ping -c 1 -t 1 8.8.8.8
   ```
4. Monitor traffic using Wireshark or tcpdump to inspect ICMP and ARP packets.
