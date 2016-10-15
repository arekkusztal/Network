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
	struct msghdr msg;

	struct sockaddr_in sina;
	sd = socket(AF_CHMLN, SOCK_DGRAM, IPPROTO_IP);
	if (sd < 0) {
		perror("socket");
		return 1;
	}

	struct iovec iov[1];
	sina.sin_family = AF_INET;
	sina.sin_port = htons(1683);
	inet_pton(AF_INET, dest_addr, &sina.sin_addr);
	printf("\naddr = %d",(int)sina.sin_addr.s_addr);
	char data[] = "areczek";

	iov[0].iov_base = data;
	iov[0].iov_len = sizeof(data);

	msg.msg_name = &sina;
	msg.msg_namelen = sizeof(sina);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = 0;
	msg.msg_controllen = 0;


  //  ret = connect(sd, (struct sockaddr *)&sina, sizeof(struct sockaddr));

	ret = sendmsg(sd, &msg, 0);
	if (ret < 0) {
		perror("connect");
			return 2;
	}

	return 0;
}
