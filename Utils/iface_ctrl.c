#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

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

int get_IFACE_IPv4(char *name)
{
    int ret;
    int sd;
    char IP[4];
    struct ifreq *if_req;

    if_req = malloc(sizeof(struct ifreq));

    sd = set_socket(if_req, name);
    if (sd < 0) {
        return sd;
    }

    ret = ioctl(sd, SIOCGIFADDR, if_req);
    if (ret < 0) {
        printf("\nError on ioctl");
        return -1;
    }

    memcpy(IP, if_req->ifr_addr.sa_data+2, 4);
    printf("\nInterface: %s", name);
    hex_dump("IP address", IP, 4, 4);

    close(sd);
    free(if_req);

    return 0;
}

int get_MAC_addr(char *name)
{
    int ret;
    int sd;
    char MAC_addr[6];
    struct ifreq *if_req;

    if_req = malloc(sizeof(struct ifreq));

    sd = set_socket(if_req, name);
    if (sd < 0) {
        return sd;
    }

    ret = ioctl(sd, SIOCGIFHWADDR, if_req);
    if (ret < 0) {
        printf("\nError on ioctl");
        return -1;
    }

    memcpy(MAC_addr, if_req->ifr_hwaddr.sa_data, 6);
    printf("\nInterface: %s", name);
    hex_dump("MAC address", MAC_addr, 6, 6);

    close(sd);
    free(if_req);
    return 0;
}

int get_IFACE_byindex(int index)
{
    int ret, sd;
    char name[IFNAMSIZ];

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
    int ret;
    int sd;
    if (getuid()) {
        printf("\nRoot yourself\n");
        return -1;
    }

    get_MAC_addr(DEVICE);
    get_IFACE_IPv4(DEVICE);
    get_IFACE_byindex(1);

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
