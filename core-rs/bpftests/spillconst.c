#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	int j = bpf_ktime_get_ns() % 100;
	bpf_printk("hello %d\n", 10 - j);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
