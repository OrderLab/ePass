#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx) {
    int t = bpf_ktime_get_ns()%10;
    if (t > 5) {
        for (int i = 0; i < t; ++i) {
            if (i > 5000) {
                return 0;
            }
            bpf_ktime_get_ns();
        }
    }else{
        __u64 t2 = bpf_ktime_get_ns();
        for (int j = 0; j < t2; ++j) {
            if (j > 5000) {
                return 0;
            }
            bpf_ktime_get_ns();
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
