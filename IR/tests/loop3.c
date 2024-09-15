#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	for (__u64 i = 0; i < 1000; ++i) {
		bpf_ktime_get_ns();
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
