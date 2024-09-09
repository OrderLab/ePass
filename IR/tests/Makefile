$(NAME).o: $(NAME).c
	clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -g -target bpf -c $< -o $@

$(NAME).nop.o: $(NAME).c
	clang -O0 -I/usr/include/$(shell uname -m)-linux-gnu -g -target bpf -c $< -o $@

$(NAME).nop.s: $(NAME).nop.o
	llvm-objdump -S $< > $@

$(NAME).s: $(NAME).o
	llvm-objdump -S $< > $@

sobj: $(NAME).s
	llvm-mc -triple bpf -filetype=obj -o $(NAME).o $(NAME).s

load: clean $(NAME).o
	sudo bpftool prog load $(NAME).o /sys/fs/bpf/$(NAME)

loadnop: clean $(NAME).nop.o
	sudo bpftool prog load $(NAME).nop.o /sys/fs/bpf/$(NAME)

attachxdp: load
	sudo bpftool net attach xdp name prog dev $(CARD)

detachxdp:
	sudo bpftool net detach xdp dev $(CARD)

log:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean: detachxdp
	rm -f $(NAME).o $(NAME).s
	-sudo rm /sys/fs/bpf/$(NAME)

.PHONY: clean load loadnop sobj attachxdp detachxdp log
