#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx)
{
    char s[1] = "a";
    bpf_printk("%c\n",s);
	return 0;
}

char _license[] SEC("license") = "GPL";
