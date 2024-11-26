#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	__u64 x = 2;
	__u64 x2 = (x << 32) >> 32;
	bpf_printk("hello %d", x2);
	return 0;
}

char _license[] SEC("license") = "GPL";
