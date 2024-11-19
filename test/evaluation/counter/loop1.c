#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx) {
    __u64 t = bpf_ktime_get_ns() % 100;
    for (__u64 i = 0; i < t; ++i) {
		if (i > 100000) {
			return 1;
		}
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
        bpf_ktime_get_ns();
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
