#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	__u64 i = 0;
	while (i < 10000) {
		__u64 a = bpf_ktime_get_ns();
		__u64 b = bpf_ktime_get_ns();
		if (a > b) {
			break;
		}
		++i;
	}
	static char msg[] = "finished:  %d";
	bpf_trace_printk(msg, sizeof(msg), i);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
