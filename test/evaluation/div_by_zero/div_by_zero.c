#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tp(void *ctx)
{
    int r0 = 0;
    int r1 = 10;
    int r2 = 10;

    if (r1 > 10)
        return 0; // r1 is in [0, 10]
    
    if (r2 > 10)
        return 0; // r2 is in [0, 10]

    r1 *= r2; // r1 is now in [0, 100]

    if (r1 != 11) // Checking if r1 is 11, but r1 can't be 11
        return 0;
    
    r1 /= r0; // Potential division by zero

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
