$(NAME).o: $(NAME).c
	clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -g -target bpf -c $< -o $@

$(NAME).nop.o: $(NAME).c
	clang -O0 -I/usr/include/$(shell uname -m)-linux-gnu -g -target bpf -c $< -o $@

$(NAME).s: $(NAME).o
	# clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -S -o $(NAME).s $(NAME).c
	llvm-objdump -S $< > $@

sobj: $(NAME).s
	llvm-mc -triple bpf -filetype=obj -o $(NAME).o $(NAME).s

load: clean $(NAME).o
	sudo bpftool prog load $(NAME).o /sys/fs/bpf/$(NAME)

loadnop: clean $(NAME).nop.o
	sudo bpftool prog load $(NAME).nop.o /sys/fs/bpf/$(NAME)

clean:
	rm -f $(NAME).o $(NAME).s
	-sudo rm /sys/fs/bpf/$(NAME)
