#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


SEC("tracepoint/syscalls/sys_enter_mount")
int count_getpid(void *ctx)
{
    return 0;
}

char _license[] SEC("license") = "GPL";
