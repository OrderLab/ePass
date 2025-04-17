#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	int arr[10];
	arr[5] = 0;
	int k = bpf_ktime_get_ns() % 10;
	if (k > 7 || k < 3) {
		return XDP_PASS;
	}
	if (arr[k] == 0) {
		bpf_printk("k = 5");
	} else {
		bpf_printk("uninit");
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
