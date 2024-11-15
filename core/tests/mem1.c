#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
    int arr[10] = {0};
    bpf_printk("%d", arr[-100]);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
