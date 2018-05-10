#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORTNO 16971
uint8_t buffer[256];
uint8_t *message = "The message";
const char *IP = "127.0.0.1";

int main(int argc, char *argv[])
{
	int ret;
	int msock;
	struct sockaddr_in addr_server;

    inet_pton(AF_INET, IP , &addr_server.sin_addr);
	addr_server.sin_family = AF_INET;
	addr_server.sin_port = htons(PORTNO);

	msock = socket(AF_INET, SOCK_STREAM, 0);
	if (msock < 0) {
		printf("\nError on creatin socket");
		return -1;
	}

	ret = connect(msock, (struct sockaddr *)&addr_server, sizeof(struct sockaddr) );
	if (ret < 0) {
		printf("\nArror on connect = %d", ret);
		close(msock);
		return -2;
	}

	memcpy(buffer, message, 11);
	ret = write(msock, buffer, 11);
	if (ret < 0) {
		printf("\nError writing to socket");
		close(msock);
		return -3;
	}
	sleep(5);
	close(msock);
	return 0;
}
