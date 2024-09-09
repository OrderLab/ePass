#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	static char msg[] = "hello\n";
	bpf_trace_printk(msg, sizeof(msg));
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
