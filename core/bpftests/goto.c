#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	bpf_ktime_get_ns();
	asm volatile(".byte 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00" ::
			     :);
	bpf_ktime_get_ns();

	return 0;
}

char _license[] SEC("license") = "GPL";
