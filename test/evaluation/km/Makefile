obj-m += llbench.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

init_ll.o: llbench_bpf.c
	clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -g -c $< -o init_ll.o

lookup_ll.o: llbench_lookup_bpf.c
	clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -g -c $< -o lookup_ll.o

cleanobj:
	rm -f init_ll.o lookup_ll.o
	sudo rm -f /sys/fs/bpf/llbench

autoattach: cleanobj init_ll.o lookup_ll.o
	sudo bpftool prog load init_ll.o /sys/fs/bpf/llbench autoattach

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

log:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

loader: loader.c
	clang -O2 loader.c -lbpf -o loader

.PHONY: clean cleanobj log
