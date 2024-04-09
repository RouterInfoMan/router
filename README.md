
# Dataplane Router

A simple dataplane router implementation capable of ARP, Forwarding, and replying to ICMP requests.

First homework for PCom Course at ACS UPB.
## Usage

Requires gcc.
Compile using ```make all```.

Run router using ```make run_routerX```.
## Ethernet

The router will not process packet that are not destined for it, but it will check broadcasts.
## ARP

The router supports ARP requests and replies and has a small table for keeping the entries.
## Forwarding

The router forwards packets using static routes read from a file. The routes are stored in a trie and contain the next hop and its respective interface.

If there is no ARP entry for the next hop then the packet will be put on hold and an ARP request for the next hop will be sent.

The router sends an ICMP Time Exceeded when the TTL of the packet reaches <= 1 and sends an ICMP Destination Net Unreachable when it finds no valid route.
## Trie
A simple binary trie was used for storing the next hops and interfaces and can be created, queries, and filled via the methods in lpm_trie.h
## ICMP

The router will respond to ICMP Echo Requests.
