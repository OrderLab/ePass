#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	for (__u64 i = 0; i < 100; ++i) {
		__u64 k = bpf_ktime_get_ns() % 100;
		k = k/10 + k/3 + k/7 - i;
		bpf_printk("%llu", k);
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";