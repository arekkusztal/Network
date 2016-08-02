/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2016 Arek Kusztal. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in
 *	   the documentation and/or other materials provided with the
 *	   distribution.
 *	 * Neither the name of Network Project nor the names of its
 *	   contributors may be used to endorse or promote products derived
 *	   from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
} __attribute__((packed));

struct ethernet2 {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t protocol;
} __attribute__((packed));

struct arp_frame {
	struct ethernet2 eth2;
	struct arp arp;
} __attribute__((packed));

int main(int argc, char *argv[])
{
	int ret;
	int sd;
	struct ifreq *ifr;
	struct sockaddr_ll device;
	struct arp_frame *arp_frame =
			malloc(sizeof(struct arp_frame));

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

	memset(&device, 0, sizeof(device));
	device.sll_ifindex = if_nametoindex(ehtdev);
	if (!device.sll_ifindex) {
		printf("\n----\nError 1: Error on name to index"
				"\nExiting...\n");
		return -1;
	}

	device.sll_family = AF_PACKET;
	memcpy(device.sll_addr, ifr->ifr_hwaddr.sa_data, 6);

	memset(arp_frame->eth2.dst, 0xFF, 6);
	memcpy(arp_frame->eth2.src, ifr->ifr_hwaddr.sa_data, 6);
	arp_frame->eth2.protocol = htons(0x0806);

	arp_frame->arp.hardware_type = htons(1);
	arp_frame->arp.protocol_type = htons(0x800);
	arp_frame->arp.hardware_size = 6;
	arp_frame->arp.protocol_size = 4;
	arp_frame->arp.operation = htons(1);
	memcpy(arp_frame->arp.sender_mac, ifr->ifr_hwaddr.sa_data, 6);
	inet_pton(AF_INET, sender_ip, arp_frame->arp.sender_ip);
	inet_pton(AF_INET, target_ip, arp_frame->arp.target_ip);

	sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sd < 0) {
		printf("\n----\nError 3: Error on socket PF_PACKET"
				"\nExiting...\n");
		close(sd);
		return -3;
	}

	ret = sendto(sd, arp_frame, sizeof(*arp_frame), 0,
			(struct sockaddr *)&device, sizeof(device));

	if (ret < 0) {
		printf("\n----\nError 3: Error on sending"
				"\nExiting...\n");
		close(sd);
		return -4;

	}
	hex_dump("Arp Eth", (uint8_t *)arp_frame ,sizeof(*arp_frame) ,16);

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
