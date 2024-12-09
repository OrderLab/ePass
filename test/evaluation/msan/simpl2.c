#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Use O0 to compile

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
