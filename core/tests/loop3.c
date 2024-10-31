#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	for (__u64 i = 0; i < 500; ++i) {
		bpf_ktime_get_ns();
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

// Plain avg: 14260 ns
// Add counter: 18303 ns
