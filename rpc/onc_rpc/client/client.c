#include <stdio.h>
#include <base.h>


int main(int argc, char *argv[])
{
    CLIENT *client;   /* clnt.h */
    int *result;
    char *server, *msg;

    if (argc != 3) {
        fprintf(stderr, "usage: %s host message\n", argv[0]);
        exit(1);
    }

    server = argv[1];
    msg = argv[2];

    client = clnt_create(server, MSGEXCHANGE,
                                PRINTMSGV,
                                "tcp");

    if (client == (CLIENT *)NULL) {
        clnt_pcreateerror(server);
        exit(1);
    }

    result = printmsg_1(&msg, client);
    if (result == (int *)NULL) {
        clnt_perror(client, server);
        exit(1);
    }

    if (*result == 0) {
        fprintf(stderr, "%s: error on printung\n", argv[0]);
        exit(1);
    }

    printf("Message delivered to %s\n", server);

    clnt_destroy(client);

    return 0;
}
