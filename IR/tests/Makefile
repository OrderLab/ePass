$(NAME).o: $(NAME).c
	clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -g -target bpf -c $< -o $@

$(NAME).s: $(NAME).o
	# clang -O2 -I/usr/include/$(shell uname -m)-linux-gnu -target bpf -S -o $(NAME).s $(NAME).c
	llvm-objdump -S $< > $@

sobj: $(NAME).S
	llvm-mc -triple bpf -filetype=obj -o $(NAME).o $(NAME).S

load:
	sudo bpftool prog load $(NAME).o /sys/fs/bpf/$(NAME)

clean:
	rm -f $(NAME).o $(NAME).S
	sudo rm /sys/fs/bpf/$(NAME)
