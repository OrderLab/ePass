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

    Err: invalid unbounded variable-offset write to stack R2
 */

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	int id = bpf_ktime_get_ns() % 20; // We cannot use 10 here
	__u64 arr[10] = {};
	for (__u32 i = 0; i < 10; ++i) {
		arr[i] = i;
	}
	call(arr[9]); // Pass
	// call(arr[10]);  // Not Pass
	// call(arr[11]);  // Not Pass
	if (id > 9 || id < 0) { // Work
		goto end;
	}
	__u64 res = arr[id];
	call(res);
#pragma nounroll
	for (__u32 i = 0; i < 10; ++i) {
		call(arr[i]);
		arr[i] = i + 1;
	}
end:
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
