#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(struct xdp_md *ctx)
{
	int i[10];
	// bpf_printk("%d\n", i[7]);
	return i[3] + 1;
}

// Removing the license section means the verifier won't let you use
// GPL-licensed helpers
char LICENSE[] SEC("license") = "Dual BSD/GPL";
