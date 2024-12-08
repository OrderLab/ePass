#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx) {
    __u64 t = bpf_ktime_get_ns();
    for (int i = 0; i < t; ++i) {
		if (i > 10) {
			return 0;
		}
        for (int j = 0; j < 1000; ++j) {
            bpf_ktime_get_ns();
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
