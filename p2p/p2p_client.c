#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>


#define LOOPBACK "127.0.0.1"
#define PORT 16971

int main()
{
	int listen_sock, ret;
	struct sockaddr_in cliaddr, __me;

	listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sock < 0) {
		perror("Error opening socket");
		return listen_sock;
	}

	memset(&__me, 0, sizeof(__me));
	__me.sin_family = AF_INET;
	__me.sin_addr.s_addr = htonl(INADDR_ANY);
	__me.sin_port = htons(PORT);

	ret = bind(listen_sock, (struct sockaddr *)&__me, sizeof(__me));
	if (ret < 0) {
		perror("Error binding");
		return ret;
	}

	ret = listen(listen_sock, 5);
	if (ret < 0) {
		perror("Error on listen");
		return ret;
	}


	close(listen_sock);
	return 0;
}
