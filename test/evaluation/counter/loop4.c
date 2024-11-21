#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	int tot = 0;
	__u64 t = bpf_ktime_get_ns() % 10;
	if (t < 1 || t > 5){
		return XDP_PASS;
	}
	for (__u64 i = 0; i < t; ++i) {
		__u64 tmp = bpf_ktime_get_ns() % 7;
		tot += tmp;
	}
	bpf_printk("%d", tot);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
