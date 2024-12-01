#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx)
{
	int tot = 0;
	__u64 t = bpf_ktime_get_ns() % 10000;
	if (t < 1 || t > 9000){
		return 0;
	}
	for (__u64 i = 0; i < t; ++i) {
		__u64 tmp = bpf_ktime_get_ns() % 7;
		tot += tmp;
	}
	bpf_printk("%d", tot);
	return 0;
}

char _license[] SEC("license") = "GPL";
