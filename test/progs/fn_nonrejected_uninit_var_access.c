#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

int f() {
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tracepoint(void *ctx) {
    int x;
    if (f()) {
        x = 1;
    }
    bpf_printk("%d\n", x); // prints 1 :/
    return x;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
