#include <stdio.h>
#include <base.h>

int * printmsg_1_svc(char **argv, struct svc_req *req)
{
    static int result = 1;
    printf("Message %s\n", (char *)*argv);
    return &result;
}
