#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	// testing negative value
	int x = bpf_ktime_get_ns() % 10;
	bpf_printk("%d", x);
	bpf_printk("%d", -x);
	return 0;
}

char _license[] SEC("license") = "GPL";
