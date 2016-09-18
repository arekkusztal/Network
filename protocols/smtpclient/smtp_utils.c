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
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>

#include "smtp.h"

const char B_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz0123456789+/";

uint32_t SMTP_strlen(uint8_t *msg)
{
	uint8_t p;
	uint32_t i;

	i = 0;
	while(msg[i] != '\r' && msg[i] != '\n' && msg[i] != ' ')
		i++;

	return i;
}

int host_to_ip(uint8_t *ip, uint8_t *name)
{
	int i;
	struct hostent *he;
	struct in_addr **addr_list;

	if ( (he = gethostbyname(name)) == NULL) {
		printf("\nERR: Cannot get host by name" __FILE__);
		return -1;
	}

	addr_list = (struct in_addr **)he->h_addr_list;
	for (i=0; addr_list[i] != NULL; i++) {
		strcpy(ip, inet_ntoa(*addr_list[i]));
		return 0;
	}

	return -1;
}

uint8_t *strtbase64(uint8_t *msg, uint32_t sz)
{
	int i, k;
	uint8_t *out, *mess;
	uint32_t tlen, diff;

	diff = sz % 3;
	sz = 4*sz/3;
	tlen =  (sz & ~3) + 4*(!!(sz & 3));


	//printf("\n %u \n %u",sz,diff);
	mess = malloc(tlen);
	memset(mess, 0, tlen);

	for (i = 0; i< sz; i++) {
		mess[tlen - i-1] = msg[i];
	}

	out = malloc(sz + sz/3 + 2);
	memset(out, 0, sz + sz/3 + 2);

	i = 0;
	for (k =0; k < tlen; k++) {
		if (k % 4 == 0 && k)
			i++;
		uint32_t dword = *(uint32_t *)&mess[tlen - 4 -3*i];
		uint8_t off = 26 - (k % 4)*6;
		dword <<= 26 - off;
		dword >>= 26;
		out[k] = B_64[dword];
	}

	if (diff == 1) {
		out[tlen-1] = '=';
		out[tlen-2] = '=';
	}
	else if (diff == 2)
		out[tlen-1] = '=';

	free(mess);

	return out;
}
