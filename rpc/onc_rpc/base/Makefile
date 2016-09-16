CFLAGS=-I$(PWD)
all:
	rpcgen base.x
	gcc -c base_svc.c
	gcc -c base_clnt.c
.PHONY:
clean:
	rm -f base.h base_clnt.c base_svc.c *.o
