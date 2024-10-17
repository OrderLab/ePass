
obj: $(NAME).c vmlinux.h
	clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -g -c $< -o output/$(NAME).o

objnop: $(NAME).c vmlinux.h
	clang -O0 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -g -c $< -o output/$(NAME).o

s: obj
	llvm-objdump -S output/$(NAME).o > output/$(NAME).s

# sobj: $(NAME).s
# 	llvm-mc -triple bpf -filetype=obj -o $(NAME).o $(NAME).s

load: obj
	sudo bpftool prog load output/$(NAME).o /sys/fs/bpf/$(NAME)

attachxdp: load
	sudo bpftool net attach xdp name prog dev $(CARD)

detachxdp:
	sudo bpftool net detach xdp dev $(CARD)

log:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f $(NAME).o $(NAME).s
	sudo rm /sys/fs/bpf/$(NAME)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

cleanall:
	rm -f *.o *.s

.PHONY: clean cleanall load obj objnop sobj attachxdp detachxdp log
