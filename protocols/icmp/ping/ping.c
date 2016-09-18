#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

#include <arpa/inet.h>

#define DST_ADDR    "8.8.8.8"


int main(int argc, char *argv[])
{
    int i, ret;
    int sock_icmp;

    struct ip;
    struct icmp icmp_hdr;

    struct sockaddr_in sin;

    if (geteuid()) {
        printf("\n----\nError 1: Root yourself"
                            "\nExiting...\n");
        return -1;
    }

    if ( (sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("Icmp error");
        return sock_icmp;
    }

 /*   const int one = 1;
    if ( (ret = setsockopt(sock_icmp, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) ) < 0 ) {
        perror("set sock opt");
        return ret;
    } */

    sin.sin_port = 7;
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, DST_ADDR, &sin.sin_addr);


    icmp_hdr.icmp_type  = ICMP_ECHO;
    icmp_hdr.icmp_code  = 0;
    icmp_hdr.icmp_cksum = htons(0xF7FE);
    icmp_hdr.icmp_id    = 0;
    icmp_hdr.icmp_seq   = htons(1);
    icmp_hdr.icmp_ttime = 0;

    if ( (ret < sendto(sock_icmp, &icmp_hdr, sizeof(struct icmphdr), 0,
                       (struct sockaddr *)&sin, sizeof(sin)))) {
        perror("sendto");
    }

    printf("\n%u", sizeof(icmp_hdr));

    close(sock_icmp);

    return 0;
}
