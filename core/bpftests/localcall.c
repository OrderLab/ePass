#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__attribute__((noinline)) static int test(int i)
{
	return bpf_ktime_get_ns() % 10;
}

__attribute__((noinline)) static int test2(int i)
{
	return bpf_ktime_get_ns() % 20;
}

SEC("xdp")
int prog(void *ctx)
{
	static int a[10];
	int j = bpf_ktime_get_ns() % 10;
	int k = test(j);
	k += test2(j);
	a[k] = 0;
	bpf_printk("hello %d", k);
	bpf_printk("hello %d", a[4]);
	return 0;
}

char _license[] SEC("license") = "GPL";
