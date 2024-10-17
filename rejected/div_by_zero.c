#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tp(void *ctx)
{
    int x = 0;
    for (int i = 0; i <= 10; i++) {
        for (int j = 0; j <= 10; j++) {
            if (i > 10) {
                i /= x;
                return 0;
            }
            if (j > 10) {
                i /= x;
                return 0;
            }
            i *= j;
            if (i != 11) {
                i /= x;
                return 0;
            }
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
