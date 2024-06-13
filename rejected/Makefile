$(NAME).o: $(NAME).c
	clang -O1 -I/usr/include/$(shell uname -m)-linux-gnu -g -target bpf -c $< -o $@

$(NAME).S: $(NAME).o
	llvm-objdump -S $< > $@

load: $(NAME).o
	sudo bpftool prog load $(NAME).o /sys/fs/bpf/$(NAME)

clean:
	rm -f $(NAME).o $(NAME).S
	sudo rm /sys/fs/bpf/$(NAME)
