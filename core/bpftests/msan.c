#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	int arr[10];
	for (int i = 0; i < 10; ++i) {
		arr[i] = i;
	}
	int k = bpf_ktime_get_ns() % 10;
	if (k > 7 || k < 4) {
		return XDP_PASS;
	}
	bpf_printk("%d", arr[k]);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
