#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include <unistd.h>


#define LOOPBACK "127.0.0.1"
#define PORT 16971

int main()
{
	int listen_sock, client_sock, ret, nready;
	int client[FD_SETSIZE];
	int max_fd;
	ssize_t n;

	char buf[16];

	socklen_t clilen;

	fd_set allset, rset;
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

	FD_ZERO(&allset);
	FD_SET(listen_sock, &allset);

	printf("\n listen fd = %d", listen_sock);

	clilen = sizeof(struct sockaddr);
	max_fd = listen_sock;

	while (1) {
		rset = allset;
		printf("\n Wait for connection\n");
		nready = select(max_fd + 1, &rset, NULL, NULL, NULL);
		printf("\n Connection in progress on nready = %d", nready);

		if (FD_ISSET(listen_sock, &rset)) {
			client_sock = accept(listen_sock, (struct sockaddr *)&cliaddr, &clilen);
			printf("\nAccepted connection %d", client_sock);
			FD_SET(client_sock, &allset);
			if (client_sock > max_fd) max_fd = client_sock;
		}
		n = read(client_sock, buf, 16);
		printf("\nSocket read %d characters", (int)n);
		if (n == 0) {
			FD_CLR(client_sock, &allset);
			close(client_sock);
		}


	}

	close(listen_sock);
	return 0;
}
