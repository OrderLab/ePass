#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	// bpf_ktime_get_ns();
	for (__u64 i = 0; i < 1000; ++i) {
		bpf_ktime_get_ns();
	}
	static char msg[] = "finished";
	bpf_trace_printk(msg, sizeof(msg));
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
