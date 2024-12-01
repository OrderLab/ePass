#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx)
{
	__u64 i = 0;
	while (i < 1000) {
		__u64 a = bpf_ktime_get_ns();
		__u64 b = bpf_ktime_get_ns();
		++i;
	}
	static char msg[] = "finished:  %d";
	bpf_trace_printk(msg, sizeof(msg), i);
	return 0;
}

char _license[] SEC("license") = "GPL";
