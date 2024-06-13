#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/**
    Using function
 */

int res(void *ctx){
    if (ctx) {
        return 10000;
    }else{
        return 0;
    }
}

SEC("xdp")
int prog(void *ctx) {
    for (int i = 0; i < res(ctx); ++i) {
        bpf_trace_printk("s", 1);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
