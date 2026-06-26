#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	bpf_trace_printk("hello\n", 7);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
