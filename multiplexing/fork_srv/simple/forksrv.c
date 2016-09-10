#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <signal.h>

#define     PORT      1683
#define     CHUNKSIZE 1024

char        buffer[CHUNKSIZE];

void sig_handler(int signo)
{
    printf("\nChild done");
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main()
{
    int pid;
    int     sockfd_main,sockfd_new;
    struct  sockaddr_in addr_main;

    if ( (sockfd_main = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
    {
        printf("Error resolving socket\n");
        return 1;
    }

    int val = 1;
    if ( (setsockopt(sockfd_main,SOL_SOCKET,SO_REUSEADDR,&val, sizeof(val))) < 0)
    {
        printf("Error on setting\n");
        return 1;
    }

    addr_main.sin_family      = AF_INET;
    addr_main.sin_addr.s_addr = INADDR_ANY;
    addr_main.sin_port        = htons(PORT);

    if ( bind(sockfd_main,(struct sockaddr*)&addr_main,sizeof(addr_main)) < 0)
    {
        printf("Error on binding\n");
        return 1;
    }

    if (listen(sockfd_main,5) == -1)
    {
        printf("Error on listen\n");
        return 1;
    }

    signal(SIGCHLD, sig_handler);
    while (1)
    {
        sockfd_new = accept(sockfd_main,NULL,NULL);
        if ( (pid = fork()) == 0)
        {
            printf("Child process created %d \n",getpid());
            recv(sockfd_new,buffer,CHUNKSIZE,0);
            printf("Child process %i received: %s\n",getpid(),buffer);
            close(sockfd_new);
            exit(0);
        }
        close(sockfd_new);
    }


    close(sockfd_main);
    return 0;
}
