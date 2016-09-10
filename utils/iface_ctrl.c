#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#define DEVICE  "eth0"

void hex_dump(const char *def, uint8_t *data, uint16_t len,
        uint16_t br);



int set_socket(struct ifreq *if_req, char *name)
{
    int sd;

    memset(if_req, 0, sizeof(struct ifreq));
    strcpy(if_req->ifr_name, name);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        printf("\nError on creating socket");
        return -sd;
    }

    return sd;
}

static inline int
if_IOCTL(struct ifreq *if_req, unsigned long SIOC, char *name)
{
    int ret;
    int sd;

    sd = set_socket(if_req, name);
    if (sd < 0) {
        return sd;
    }

    ret = ioctl(sd, SIOC, if_req);
    if (ret < 0) {
        printf("\nError on ioctl");
        return -1;
    }

    close(sd);

}

int get_IFACE_IPv4(char *IP, char *name)
{
    int ret;
    struct ifreq *if_req;

    if_req = malloc(sizeof(struct ifreq));

    if (ret = if_IOCTL(if_req, SIOCGIFADDR, name)) {
        return ret;
    }

    memcpy(IP, if_req->ifr_addr.sa_data+2, 4);

    free(if_req);

    return 0;
}

int set_IFACE_IPv4(char *IP, char *name)
{
    int sd;
    struct ifreq *ifreq;
    struct sockaddr_in sa;

    ifreq = malloc(sizeof(struct sockaddr_in));

    sd = socket(AF_INET, SOCK_STREAM, 0);

    strncpy(ifreq->ifr_name, name, IFNAMSIZ);

    memset(&sa, 0, sizeof(struct sockaddr));
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = inet_addr(IP);

    memcpy(&ifreq->ifr_addr, &sa,
           sizeof(struct sockaddr));

    ioctl(sd, SIOCSIFADDR, ifreq);

    close(sd);

    return 0;
}

int get_MAC_addr(char *MAC_addr, char *name)
{
    int ret;
    struct ifreq *if_req;

    if_req = malloc(sizeof(struct ifreq));

    if (if_IOCTL(if_req, SIOCGIFHWADDR, name)) {
        return ret;
    }

    memcpy(MAC_addr, if_req->ifr_hwaddr.sa_data, 6);

    free(if_req);

    return 0;
}

int get_IFACE_flags(short *FLAGS, char *name)
{
    int ret;
    struct ifreq *if_req;

    if_req = malloc(sizeof(struct ifreq));

    if (if_IOCTL(if_req, SIOCGIFFLAGS, name)) {
        return ret;
    }

    *FLAGS = if_req->ifr_flags;

    free(if_req);

    return 0;
}

int check_FLAGS(short *FLAGS, char *name)
{
    printf("\nInterface: %s\n", name);
    get_IFACE_flags(FLAGS, name);
    if (*FLAGS & IFF_UP)
        printf("IFF_UP ");
    if (*FLAGS & IFF_BROADCAST)
        printf("IFF_BROADCAST ");
    if (*FLAGS & IFF_DEBUG)
        printf("IFF_DEBUG ");
    if (*FLAGS & IFF_LOOPBACK)
        printf("IFF_LOOPBACK ");
    if (*FLAGS & IFF_POINTOPOINT)
        printf("IFF_POINTOPOINT ");
    if (*FLAGS & IFF_NOTRAILERS)
        printf("IFF_NOTRAILERS ");
    if (*FLAGS & IFF_RUNNING)
        printf("IFF_RUNNING ");
    if (*FLAGS & IFF_NOARP)
        printf("IFF_NOARP ");
    if (*FLAGS & IFF_PROMISC)
        printf("IFF_PROMISC ");
    if (*FLAGS & IFF_ALLMULTI)
        printf("IFF_ALLMULTI ");
    if (*FLAGS & IFF_MASTER)
        printf("IFF_MASTER ");
    if (*FLAGS & IFF_SLAVE)
        printf("IFF_SLAVE ");
    if (*FLAGS & IFF_MULTICAST)
        printf("IFF_MULTICAST ");
    if (*FLAGS & IFF_PORTSEL)
        printf("IFF_PORTSEL ");
    if (*FLAGS & IFF_AUTOMEDIA)
        printf("IFF_AUTOMEDIA ");
    if (*FLAGS & IFF_DYNAMIC)
        printf("IFF_DYNAMIC ");

    printf("\n");

    return 0;
}

int get_IFACE_byindex(int index)
{
    int ret, sd;

    struct ifreq *if_req;\

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        printf("\nError on socket");
        return -1;
    }

    if_req = malloc(sizeof(struct ifreq));

    memset(if_req, 0, sizeof(struct ifreq));
    if_req->ifr_ifindex = index;

    ret = ioctl(sd, SIOCGIFNAME, if_req);
    if (ret < 0) {
        printf("\nError on ioctl");
        return -1;
    }

    printf("\nInterface[%d]: %s\n", index, if_req->ifr_name);
    close(sd);
    free(if_req);
    return 0;
}


int main(int argc, char *argv[])
{
    if (getuid()) {
        printf("\nRoot yourself\n");
        return -1;
    }

    char MAC_addr[6];
    char IP[4];
    char *IP_2 = "192.168.1.98";
    short FLAGS;

   /* get_MAC_addr(MAC_addr, DEVICE);

    printf("\nInterface: %s", DEVICE);
    hex_dump("MAC address", MAC_addr, 6, 6); */

    set_IFACE_IPv4(IP_2, DEVICE);
 /*   get_IFACE_IPv4(IP, DEVICE);

    printf("\nInterface: %s", DEVICE);
    hex_dump("IP address", IP, 4, 4);

    get_IFACE_byindex(1);

    check_FLAGS(&FLAGS, DEVICE); */

    return 0;
}

void hex_dump(const char *def, uint8_t *data, uint16_t len,
        uint16_t br)
{
    uint16_t i;

    printf("\n%s:\n", def);
    for (i = 0; i < len; ++i) {
        if (i && ( i % br ==0 ))
            printf("\n");
        printf("0x%02X ",data[i]);
    }
    printf("\n");
}
