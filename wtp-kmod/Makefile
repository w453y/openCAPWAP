# wtp-kmod/Makefile -- cross-compile CAPWAP data-plane kmod for IPQ6018

QSDK  ?= /workdir3/qsdk
KDIR  := $(QSDK)/qca/src/linux-5.4
CROSS := arm-openwrt-linux-muslgnueabi-

obj-m := wtp.o
wtp-objs := main.o capwap.o capwap_private.o netlinkapp.o

KBUILD_MODPOST_WARN := 1
ccflags-y := -I$(src)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm CROSS_COMPILE=$(CROSS) KBUILD_MODPOST_WARN=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=arm clean

.PHONY: all clean
