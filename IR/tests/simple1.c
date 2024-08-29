#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	bpf_trace_printk("abcd", 2);
	return 0;
}

char _license[] SEC("license") = "GPL";
