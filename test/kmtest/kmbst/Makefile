obj-m += bstkm.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	
bst.o: bst_bpf.c
	clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -g -c $< -o bst.o

cleanobj:
	rm -f bst.o
	sudo rm -f /sys/fs/bpf/bst

autoattach: cleanobj bst.o
	sudo bpftool prog load bst.o /sys/fs/bpf/bst autoattach

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

log:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

loader: loader.c
	clang -O2 loader.c -lbpf -o loader

.PHONY: clean cleanobj log
