#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	__u64 t = bpf_ktime_get_ns();
	bpf_trace_printk("100", t % 3);
	return 0;
}

char _license[] SEC("license") = "GPL";
