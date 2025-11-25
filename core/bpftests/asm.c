#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static __always_inline long emit_ec(long x)
{
	register long r1 asm("r1") = x; // src = r1
	register long r0 asm("r0"); // dst = r0
	asm volatile(".byte 0x85, 0x61, 0,0,0,0,0,0\n" : "=r"(r0) : "r"(r1) :);
	return r0;
}

SEC("xdp")
int prog(void *ctx)
{
	long xx = 123;
	long bb = emit_ec(xx);
	bpf_printk("ecall returned: %ld\n", bb);
	return 0;
}

char _license[] SEC("license") = "GPL";
