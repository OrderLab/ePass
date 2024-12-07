#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tp(void *ctx)
{
    int r0 = bpf_ktime_get_ns() % 2;
    if (r0 == 1){
        return 0;
    }
    bpf_printk("%d\n", 10 / r0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
