#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	__u64 t = bpf_ktime_get_ns();
	bpf_trace_printk("%lld\n", 6, t);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
