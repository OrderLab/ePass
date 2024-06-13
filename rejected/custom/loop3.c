#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/**
    OK, verifier wont't check how large the loop is
 */

SEC("xdp")
int prog(void *ctx) {
    for (int i = 0; i < 100000; ++i) {
        bpf_trace_printk("s", 1);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
