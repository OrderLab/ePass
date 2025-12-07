#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_mount")
int prog(void *ctx)
{

    volatile int a;
	bpf_printk("r10 - 8: %p: %d\n", &a, a);
    long* r10 = (long*)((int*)(&a) + 1);
	bpf_printk("r10: %p: %d\n", r10, *r10); // Invalid

	bpf_printk("entry_prog: tail call failed\n");
	return XDP_PASS;
}
