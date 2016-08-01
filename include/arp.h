#ifndef ARP_H
#define ARP_H

#include <stdint.h>

enum HARDWARE_TYPE {
	ETHERNET = 1,
	EXP_ETHERNET,
	AX_25,
	PRONET_TOKEN_RING,
	CHAOS = 5,
	IEEE_802,
	ARCNET,
	HYPERCHANNEL,
	LANSTAR,
	AUTONET_SHORT_ADDRESS = 10,
	/* TODO */
};

struct arp {
	uint16_t hardware_type,
	uint16_t protocol_type,
	uint8_t hardware_size,
	uint8_t protocol_size,
	uint16_t operation,
	uint8_t sender_mac[6],
	uint8_t sender_ip[4],
	uint8_t target_mac[6],
	uint8_t target_ip[4],
};



#endif
