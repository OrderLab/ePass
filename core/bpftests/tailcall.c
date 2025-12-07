// tailcall_kern.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Program array map
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} jmp_table SEC(".maps");

// Entry program
SEC("tracepoint/syscalls/sys_enter_mount")
int entry_prog(void *ctx)
{
	__u32 index = 1;

	// int a[5] = { 1, 2, 3, 4, 5 };
    volatile int a = 100;
	bpf_printk("p1 %p\n", &a);

	// Tail call to index 1
	bpf_tail_call(ctx, &jmp_table, index);

	bpf_printk("entry_prog: tail call failed\n");
	return XDP_PASS;
}

// Program that is tail-called
SEC("tracepoint/syscalls/sys_enter_mount")
int next_prog(void *ctx)
{
    volatile int a;
	bpf_printk("p2 %p\n", &a);
	bpf_printk("p2 %d\n", a);
	return XDP_PASS;
}
