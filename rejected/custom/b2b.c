#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

void __noinline call1() {
    bpf_trace_printk("hello", 6);
}

void __noinline call2() {
    bpf_trace_printk("world", 6);
}

SEC("xdp")
int prog(void *ctx) {
    call1();
    call2();
    return 0;
}

char _license[] SEC("license") = "GPL";
