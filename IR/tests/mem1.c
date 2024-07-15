#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/**
    Invalid memory access

    Err: math between fp pointer and register with unbounded min value is not allowed
 */

SEC("xdp")
int prog(void *ctx) {
    int id = bpf_ktime_get_ns() % 10;
    int arr[10] = {};
    for (int i = 0; i < 10; ++i) {
        arr[i] = i;
    }
    if (id > 10 || id < 0) {
        return 0;
    }
    bpf_trace_printk("%d", 1, arr[id]);
    return 0;
}

char _license[] SEC("license") = "GPL";
