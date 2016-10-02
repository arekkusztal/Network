obj-m+=chameleon.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
.PHONY:
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules clean
