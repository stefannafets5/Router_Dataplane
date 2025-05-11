#include <unistd.h>
#include <stdint.h>

/* Ethernet ARP packet from RFC 826 */
struct arp_hdr {
	uint16_t hw_type;   /* Format of hardware address */
	uint16_t proto_type;   /* Format of protocol address */
	uint8_t hw_len;    /* Length of hardware address */
	uint8_t proto_len;    /* Length of protocol address */
	uint16_t opcode;    /* ARP opcode (command) */
	uint8_t shwa[6];  /* Sender hardware address */
	uint32_t sprotoa;   /* Sender IP address */
	uint8_t thwa[6];  /* Target hardware address */
	uint32_t tprotoa;   /* Target IP address */
} __attribute__((packed));

/* Ethernet frame header*/
struct  ether_hdr {
    uint8_t  ethr_dhost[6];
    uint8_t  ethr_shost[6];
    uint16_t ethr_type;
};

/* IP Header */
struct ip_hdr {
    uint8_t    ihl:4, ver:4;
    uint8_t    tos;
    uint16_t   tot_len;
    uint16_t   id;
    uint16_t   frag;
    uint8_t    ttl;
    uint8_t    proto;
    uint16_t   checksum;
    uint32_t   source_addr;
    uint32_t   dest_addr;
};

struct icmp_hdr
{
  uint8_t mtype;                /* message type */
  uint8_t mcode;                /* type sub-code */
  uint16_t check;               /* checksum */
  union
  {
    struct
    {
      uint16_t        id;
      uint16_t        seq;
    } echo_t;                        /* echo datagram */
    uint32_t        gateway_addr;        /* Gateway address */
    struct
    {
      uint16_t        __unused;
      uint16_t        mtu;
    } frag_t;
  } un_t;
};
