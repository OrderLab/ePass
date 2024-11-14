#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int some_function(int *ptr) {
    *ptr = 5;
    return 0;
}

int handle_tracepoint(void *ctx) {
    int value;
    some_function(&value); // Verifier rejects this
    return value;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
