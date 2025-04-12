#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__attribute__((noinline)) static int test(int i)
{
	return i + 1;
}

__attribute__((noinline)) static int test2(int i)
{
	return i * 2;
}

SEC("xdp")
int prog(void *ctx)
{
	int t = bpf_ktime_get_ns() % 10;
	int res = test(t);
	int res2 = test2(res);
	bpf_printk("%d\n", res2);
	return 0;
}

char _license[] SEC("license") = "GPL";
