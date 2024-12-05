#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx)
{
	for (__u64 i = 0; i < 10000; ++i) {
		__u64 k = bpf_ktime_get_ns() % 100;
		k = k/10 + k/3 + k/7 - i;
		bpf_printk("%llu", k);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
