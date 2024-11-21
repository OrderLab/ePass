#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")

int handle_tracepoint(void *ctx) {
    int arr[10];
    int *ptr = arr;
    int index = 3;
    
    ptr += index * 7 - 1;

    *ptr = 5;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
