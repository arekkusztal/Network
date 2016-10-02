#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define AF_CHMLN	12
#define dest_addr 	"127.0.1.1"

int main(int argc, char *argv[])
{
        int sd, ret;
        struct sockaddr_in sin;

	sd = socket(AF_CHMLN, SOCK_STREAM, IPPROTO_IP);
	if (sd < 0) {
		perror("socket");
		return 1;
	}

        sin.sin_family = AF_CHMLN;
        sin.sin_port = 1683;
        inet_pton(AF_INET, dest_addr, &sin.sin_addr);

        ret = connect(sd, (struct sockaddr *)&sin, sizeof(struct sockaddr));
        if (ret < 0) {
            perror("connect");
                return 2;
        }

	return 0;
}
