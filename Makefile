CS5434 := sniffer
CS5434_MODNAME := sniffer_mod
DIST_FILE=sniffer.tar.gz

EXTRA_CFLAGS = -O3

ifneq ($(KERNELRELEASE),)
# in Kernel
obj-m := $(CS5434_MODNAME).o
$(CS5434_MODNAME)-objs := $(CS5434).o 

else
KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
KSRC := /lib/modules/$(KVER)/source
PWD := $(shell pwd)

all: default firewall_control sniffer_read hashtable
#all: default tester 

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
	rm -f firewall_control sniffer_read hashtable *.tar.gz *.dev

dist: clean
	tar -czf $(DIST_FILE) ../sniffer --exclude=$(DIST_FILE) --exclude=".svn"

endif

CC = gcc -Wall

firewall_control: firewall_control.c 
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(EXTRA_CFLAGS) $^ 

sniffer_read: sniffer_read.c 
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(EXTRA_CFLAGS) $^ 

hashtable: hashtable.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(EXTRA_CFLAGS) $^ 