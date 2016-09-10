#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

char buffer[256];

int main()
{
    int ret;
    int val, iter;
    int listensock, sd;
    struct sockaddr_in sa;
    fd_set readset, tempset;

    listensock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listensock < 0) {
        perror("Server");
        return -1;
    }

    val = 1;
    ret = setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &val,
                     sizeof(val));

    if (ret < 0) {
        perror("Server");
        return -2;
    }

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(1683);

    ret = bind(listensock, (struct sockaddr *)&sa, sizeof(struct sockaddr_in));
    if (ret < 0) {
        perror("Server");
        return -3;
    }

    ret = listen(listensock, 5);
    if (ret < 0) {
        perror("Server");
        return -4;
    }

    FD_ZERO(&readset);
    FD_SET(listensock, &readset);

    while (1)
    {
        tempset = readset;
        ret = select(FD_SETSIZE, &tempset, NULL, NULL, NULL);
        printf("\nSELECTED:..");
        if (ret < 1) {
           perror("Server");
           return -5;
        }
      //  getc(stdin);

        for (iter = 0; iter < FD_SETSIZE; ++iter)
            if (FD_ISSET(iter, &tempset))
                if (iter == listensock) {
                    sd = accept(listensock, NULL, NULL);
                    FD_SET(sd, &readset);
                    printf("\nConnected with %d %d",sd, listensock);
                }
                else {
                    ret = recv(sd, buffer, 256, 0);
                    if (ret <= 0) {
                        close(iter);
                        FD_CLR(iter, &readset);
                        printf("\nClient on %d disconnected", iter);
                    } else {
                        buffer[ret+1] = '\0';
                        printf("\nRecv on %d: %s",sd, buffer);
                        send(sd, buffer, ret, 0);
                    }
                }


    }


    close(listensock);

    return 0;
}
