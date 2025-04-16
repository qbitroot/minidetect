obj-m := minidetect.o

KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	cp minidetect.ko /lib/modules/$(shell uname -r)/kernel/drivers/misc/
	depmod -a

uninstall:
	rm -f /lib/modules/$(shell uname -r)/kernel/drivers/misc/minidetect.ko
	depmod -a


.PHONY: all clean install uninstall
