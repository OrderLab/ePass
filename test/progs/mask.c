#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define SIZE 100

SEC("xdp")
int prog(void *ctx)
{
	int t = bpf_ktime_get_ns() % SIZE;
	static int a[SIZE] = { 0 };
	for (int i = 0; i < SIZE; ++i) {
		a[i] = i;
	}
	static char msg[] = "num:  %d";
	// if (t < 0 || t > 100) {
	// 	return 0;
	// }
	bpf_trace_printk(msg, sizeof(msg), a[t]);
	return 0;
}

char _license[] SEC("license") = "GPL";
