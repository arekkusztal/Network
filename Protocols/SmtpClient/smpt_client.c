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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

struct smtp_cmd {
	uint8_t cmd[5];
	uint8_t param[60];
};

struct smtp_resp {
	uint8_t cmd[4];
	uint8_t param[60];
};

#define SERVER_1	"212.77.101.1"//"smtp.wp.pl"
#define err(arg)	printf("Error %d",arg); \
					return -(arg);
#define SMTP_PORT	25
#define EHLO 	"EHLO "

int host_to_ip(uint8_t *ip, uint8_t *name)
{
	int i;
	struct hostent *he;
	struct in_addr **addr_list;

	if ( (he = gethostbyname(name)) == NULL) {
		printf("\nERR: Cannot get host by name" __FILE__);
		return 1;
	}

	addr_list = (struct in_addr **)he->h_addr_list;
	for (i=0; addr_list[i] != NULL; i++) {
		strcpy(ip, inet_ntoa(*addr_list[i]));
		return 0;
	}

	return 2;
}
#define BUF_LEN	1024
uint8_t ip[4];
uint8_t buffer[BUF_LEN];

int SMTP_send_req(int sd, uint8_t *cmd, uint8_t *param)
{
	int ret;
	struct smtp_cmd req;
	memcpy(req.cmd, cmd, 5);
	memcpy(req.param, param, 7);
	printf("\nSend: %s", (uint8_t *)&req);
	ret = write(sd, (uint8_t *)&req, 12);
	if (ret != 12) {
		printf("Error 3");
		return -1;
	}

	return 0;
}

struct smtp_resp resp;
int SMTP_set_connection(int sd)
{
	int ret;
	/* First response commant should be 220 (Service Ready) */
	ret = read(sd, (uint8_t *)&resp, BUF_LEN);
	if (ret < 0) {
		printf("\nError ");
		return 1;
	}
	resp.cmd[3] = '\0';
	if (memcmp(resp.cmd, "220", 3) !=0 ) {
		printf("\nError 1");
		return 1;

	}
	printf("\nINFO: Connected to %s", resp.param);

	ret = SMTP_send_req(sd, EHLO, "12345\r\n");
	if (ret < 0) {
		printf("\nError 1");
		return 1;
	}

	/* Second | Mail action ok (250) */
	ret = read(sd, (uint8_t *)&resp, BUF_LEN);
	if (ret < 0) {
		printf("\nError ");
		return 1;
	}
	resp.cmd[3] = '\0';
	if (memcmp(resp.cmd, "250", 3) !=0 ) {
		printf("\nError 1");
		return 1;

	}

	ret = SMTP_send_req(sd, "AUTH ", "LOGIN\r\n");
	if (ret < 0) {
		printf("\nError 1");
		return 1;
	}

	/* If eveything ok, we have got 'Username:' in base64 */
	ret = read(sd, (uint8_t *)&resp, BUF_LEN);
	if (ret < 0) {
		printf("\nError ");
		return 1;
	}
	return 0;
}

int main()
{
	int sd, ret;
	struct sockaddr_in sa;
	struct smtp_cmd req;

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		err(1);
	}

	sa.sin_port = htons(SMTP_PORT);
	sa.sin_family = AF_INET;
	inet_pton(AF_INET, SERVER_1, &sa.sin_addr);

	/* Enter connection state with server port 25 */
	ret = connect(sd, (struct sockaddr*)&sa, sizeof(struct sockaddr));
	if (ret < 0) {
		close(sd);
		err(2);
	}

	SMTP_set_connection(sd);

	close(sd);

	return 0;
}
