#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/**
    Calling external function results in verifier halt
 */

SEC("xdp")
int prog(void *ctx)
{
	__u64 t = bpf_ktime_get_ns();
	bpf_trace_printk(ctx, t);
	for (__u64 i = 0; i < t; ++i) {
		bpf_trace_printk("s", i);
		bpf_trace_printk(ctx, 2);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
