#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <net/if.h>

#include <sys/ioctl.h>
#include <bits/ioctls.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

const char *ehtdev = "enp0s3";
char *target_ip = "192.168.192.47";
char *sender_ip = "192.168.192.19";

void hex_dump(const char *def, uint8_t *data, uint16_t len,
		uint16_t br);

struct arp {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint16_t operation;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};

struct ethernet2 {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t protocol;
};

struct arp arp_hdr;
#define ETH2_LENGTH		14

int main(int argc, char *argv[])
{
	int ret;
	int sd;
	struct ifreq *ifr;
	struct addrinfo hints, *res;
	struct sockaddr_ll addr_ll;
	uint8_t *src_MAC = malloc(6);
	uint8_t *frame = malloc(128);


	if (geteuid()) {
		printf("\n----\nError 1: Root yourself"
				"\nExiting...\n");
		return -1;
	}

	ifr = malloc(sizeof(struct ifreq));
	memset(ifr, 0, sizeof(struct ifreq));
	strcpy(ifr->ifr_name, ehtdev);

	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sd < 0) {
		printf("\n----\nError 1: Error creating raw socket"
				"\nExiting...\n");
		return -1;
	}
	ret = ioctl(sd, SIOCGIFHWADDR, ifr);
	close(sd);
	if (ret < 0) {
		printf("\n----\nError 1: Error on ioctl"
				"\nExiting...\n");
		return -2;
	}

	memset(&addr_ll, 0, sizeof(addr_ll));
	addr_ll.sll_ifindex = if_nametoindex(ehtdev);
	if (!addr_ll.sll_ifindex) {
		printf("\n----\nError 1: Error on name to index"
				"\nExiting...\n");
		return -1;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	ret = getaddrinfo(target_ip, NULL, &hints, &res);
	if (ret) {
		printf("\n----\nError 1: Error on getaddrinf"
				"\nExiting...\n");
		return -1;
	}

	addr_ll.sll_family = AF_PACKET;
	memcpy(addr_ll.sll_addr, ifr->ifr_hwaddr.sa_data, 6);
	addr_ll.sll_halen;

	memset(frame, 0xFF, 6);
	memcpy(frame + 6, ifr->ifr_hwaddr.sa_data, 6);
	frame[12] = 0x08;
	frame[13] = 0x06;

	arp_hdr.hardware_type = htons(1);
	arp_hdr.protocol_type = htons(ETH_P_IP);
	arp_hdr.hardware_size = 6;
	arp_hdr.protocol_size = 4;
	arp_hdr.operation = htons(1);
	memcpy(arp_hdr.sender_mac, ifr->ifr_hwaddr.sa_data, 6);
	inet_pton(AF_INET, sender_ip, arp_hdr.sender_ip);
	inet_pton(AF_INET, target_ip, arp_hdr.target_ip);

	struct sockaddr_in *temp = (struct sockaddr_in *)&ifr->ifr_addr;
	hex_dump("Jebane HP", (uint8_t *)&temp->sin_addr  ,6 ,16);


	memcpy(frame + ETH2_LENGTH, &arp_hdr, sizeof(struct arp));

	sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sd < 0) {
		printf("\n----\nError 3: Error on socket PF_PACKET"
				"\nExiting...\n");
		close(sd);
		return -3;
	}

	ret = sendto(sd, frame, ETH2_LENGTH + sizeof(struct arp), 0,
			(struct sockaddr *)&addr_ll, sizeof(addr_ll));

	if (ret < 0) {
		printf("\n----\nError 3: Error on sending"
				"\nExiting...\n");
		close(sd);
		return -4;

	}
	hex_dump("Sent", frame ,sizeof(frame) + sizeof(struct arp) ,16);
	hex_dump("Addr", (uint8_t *)&addr_ll ,sizeof(addr_ll) ,16);


	close(sd);
	return 0;
}



void hex_dump(const char *def, uint8_t *data, uint16_t len,
		uint16_t br)
{
	uint16_t i;

	printf("\n%s:\n", def);
	for (i = 0; i < len; ++i) {
		if (i && ( i % br ==0 ))
			printf("\n");
		printf("0x%02X ",data[i]);
	}
	printf("\n");
}
