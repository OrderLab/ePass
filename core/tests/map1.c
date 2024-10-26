#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// int c = 10;
// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 10240);
// 	__type(key, u32);
// 	__type(value, u32);
// } my_config SEC(".maps");

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	int i[10];
	// bpf_printk("%d\n", i[0]);
	bpf_printk("%d\n", i[7]);
	// return XDP_PASS;
	// int j;
	// // char ext[5] = "abc";
	// u32 *p;
	// u32 k = 0;

	// // // This is a loop that will pass the verifier
	// // for (int i = 0; i < 10; i++) {
	// // 	bpf_printk("Looping %d", i);
	// // }
	// // if(bpf_map_update_elem(&my_config, &k, &k, BPF_ANY) != 0) {
	// //     return XDP_DROP;
	// // }
	// p = bpf_map_lookup_elem(&my_config, &i);
	// // p = bpf_map_lookup_elem(&my_config, &k);
	// if (p != 0) {
	// 	i = 10;
	// }

	// j = i + 1;
	// bpf_printk("%d", j);
	// // bpf_printk("%d", *p);
	// // if (p != 0) {
	// // 	bpf_printk("%d", *p);
	// // }
	// // ext[0] = 'a';
	// // ext[1] = '\0';
	// // bpf_printk("%c", ext[6]);
	// if (i < 5) {
	// 	bpf_printk("%d", i);
	// }

	return i[3];
}

// Removing the license section means the verifier won't let you use
// GPL-licensed helpers
char LICENSE[] SEC("license") = "Dual BSD/GPL";
