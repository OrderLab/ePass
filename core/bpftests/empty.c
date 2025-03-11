#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
