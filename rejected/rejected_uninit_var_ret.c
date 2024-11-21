#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")

int handle_tracepoint(void *ctx) {
    int x;
    if (1 == 0) {
        x = 1;
    }
    return x;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
