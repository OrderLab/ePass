#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int __noinline call(__u64 i) {
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
int prog(struct xdp_md *ctx) {
    __u64 arr[10] = {};
    for (__u32 i = 0; i < 10; ++i) {
        arr[i] = i;
    }
    call(arr[9]);  // Pass
    // call(arr[10]);  // Not Pass
    // call(arr[11]);  // Not Pass
    int id = bpf_ktime_get_ns() % 20;
    if (id > 9 || id < 0) { // Work
        goto end;
    }
    __u64 res = arr[id];
    call(res);  // Not Pass
end:
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
