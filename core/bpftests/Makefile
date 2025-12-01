
obj: $(NAME).c
	clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -c $< -o output/$(NAME).o

gobj: $(NAME).c
	clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -g -c $< -o output/$(NAME).o

objnop: $(NAME).c
	clang -O0 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -c $< -o output/$(NAME).o

s: obj
	llvm-objdump -S output/$(NAME).o > output/$(NAME).s

snop: objnop
	llvm-objdump -S output/$(NAME).o > output/$(NAME).s

load: clean obj
	sudo LIBBPF_ENABLE_EPASS=0 LIBBPF_EPASS_GOPT="verbose=3" LIBBPF_EPASS_POPT="" bpftool prog load output/$(NAME).o /sys/fs/bpf/$(NAME)

autoattach: clean obj
	sudo bpftool prog load output/$(NAME).o /sys/fs/bpf/$(NAME) autoattach

attachxdp: load
	sudo bpftool net attach xdp name prog dev $(CARD)

detachxdp:
	sudo bpftool net detach xdp dev $(CARD)

log:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f $(NAME).o $(NAME).s
	sudo rm -f /sys/fs/bpf/$(NAME)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

cleanall:
	rm -f *.o *.s

.PHONY: clean cleanall load obj objnop sobj attachxdp detachxdp log
