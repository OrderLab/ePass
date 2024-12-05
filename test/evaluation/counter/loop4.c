#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx)
{
	int tot = 0;
	__u64 t = bpf_ktime_get_ns() % 2;
	for (__u64 i = 0; i < 100; ++i) {
		__u64 tmp = bpf_ktime_get_ns() % 7;
		tot += tmp;
	}
	bpf_printk("%d", tot);
	return 0;
}

char _license[] SEC("license") = "GPL";
