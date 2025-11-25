#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[1024]);
} meta SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[1024]);
} data SEC(".maps");

static __always_inline void *malloc(void *x, void *y, long size)
{
	register long r1 asm("r1") = (long)x;
	register long r2 asm("r2") = (long)y;
	register long r3 asm("r3") = size;
	register long r0 asm("r0");
	asm volatile(".byte 0x85, 0x63, 0,0,0,0,0,0\n"
		     : "=r"(r0)
		     : "r"(r1), "r"(r2), "r"(r3)
		     :);
	return (void *)r0;
}


static __always_inline void free(void *x)
{
	register long r1 asm("r1") = (long)x;
	asm volatile(".byte 0x85, 0x61, 0,0,1,0,0,0\n"
		     : 
		     : "r"(r1)
		     :);
	return;
}

struct test_struct {
	int a;
	long b;
};

SEC("xdp")
int prog(void *ctx)
{
	struct test_struct *bb = (struct test_struct*) malloc(&meta, &data, sizeof(struct test_struct));
	bb->a = 42;
	bb->b = 123456789;
	bpf_printk("ecall returned: %d\n", bb->a);
	free(bb);
	return 0;
}

char _license[] SEC("license") = "GPL";
