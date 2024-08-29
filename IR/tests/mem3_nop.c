#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int __noinline call(__u64 i)
{
	if (i > 100) {
		return -1;
	}
	bpf_trace_printk("i: %d\n", 4, i);
	return 0;
}

/**
    Invalid memory access

    Err: invalid read from stack R10 off=72 size=8
 */

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	__u64 arr[10] = {};
	call(arr[20]); // Not Pass
	call(arr[11]); // Not Pass
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
