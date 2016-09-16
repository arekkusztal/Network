CFLAGS=-I$(PWD)/base
export CFLAGS
all:
	$(MAKE) -C base
	$(MAKE) -C server
	$(MAKE) -C client
	gcc -o srv base/base_svc.o server/server.o -lnsl
	gcc -o cli base/base_clnt.o client/client.o -lnsl
.PHONY:
clean:
	$(MAKE) -C base clean
	$(MAKE) -C server clean
	$(MAKE) -C client clean
.PHONY:
clean_all: clean
	rm -f srv cli
