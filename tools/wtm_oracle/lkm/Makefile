obj-m = khax.o
KDIR := ./linux-5.4.254
PWD := $(shell pwd)

ccflags-y := -fno-exceptions -O2 -gbtf

.PHONY: default
default:
	$(MAKE) -C $(KDIR) V=1 ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabihf- M=$(PWD)
