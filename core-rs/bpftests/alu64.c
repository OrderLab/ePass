#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	char s2[] = "1";
	bpf_trace_printk(s2, sizeof(s2));
	char s1[] = "hello world\n";
	// bpf_trace_printk(s1, sizeof(s1));
	__u64 i1 = 0x3456789abcdef0;
	__u64 i2 = 0x76543210fedcba;
	__u64 ans = i1 + i2;
	// char s[10] = {};

	// int i = 2;
	return 0;
}

char _license[] SEC("license") = "GPL";
