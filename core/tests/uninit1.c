#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	int a[20];
	int id = bpf_ktime_get_ns() % 10;
	if (id < 3 || id > 7) {
		return 0;
	}
	a[5] = 0;
	if (a[id]) {
		bpf_printk("aba\n");
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
