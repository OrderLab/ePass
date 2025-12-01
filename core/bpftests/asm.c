#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define HEAP_SIZE 1024

struct meta_entry {
	long pos;
	long size;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 257);
	__type(key, __u32);
	__type(value, struct meta_entry);
} meta SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[HEAP_SIZE]);
} data SEC(".maps");

static __always_inline int init_heap(long size)
{
	int i = 0;
	char *head = bpf_map_lookup_elem(&data, &i);
	if (head == NULL) {
		return 0;
	}

	register long r1 asm("r1") = (long)(head);
	register long r2 asm("r2") = (long)size;
	asm volatile(".byte 0x85, 0x62, 0,0,0,0,0,0\n" : : "r"(r1), "r"(r2) :);
	return 1;
}

static __always_inline void *malloc(long size)
{
	int i = 0;
	// long rv = 0;
	struct meta_entry *head = bpf_map_lookup_elem(&meta, &i);
	if (head->pos == 255) {
		head->pos = 0;
	}
	// Directly use head->pos
	// int newpos = head->pos+1;
	// We got a free space at idx head->pos and data pos head->size
	long rpos = head->size;
	int rid = head->pos + 1;
	head->pos++;
	head->size += size;

	if (bpf_map_update_elem(&meta, &i, head, BPF_ANY) != 0) {
		return NULL;
	}
	head->pos = rpos;
	head->size = size;
	i = rid;
	if (bpf_map_update_elem(&meta, &i, head, BPF_ANY) != 0) {
		return NULL;
	}
	// rv = rpos;
	// register long r1 asm("r1") = (long)(&data);
	// register long r2 asm("r2") = (long)rv;
	// register long r0 asm("r0");
	// asm volatile(".byte 0x85, 0x62, 0,0,0,0,0,0\n"
	// 	     : "=r"(r0)
	// 	     : "r"(r1), "r"(r2)
	// 	     :);
	return (void *)rpos;
}

static __always_inline void free(void *x)
{
	// register long r1 asm("r1") = (long)x;
	// asm volatile(".byte 0x85, 0x61, 0,0,1,0,0,0\n" : : "r"(r1) :);
	return;
}

struct test_struct {
	int a;
	volatile struct test_struct *next;
};

SEC("xdp")
int prog(void *ctx)
{
	if (init_heap(HEAP_SIZE) == 0) {
		return XDP_PASS;
	}
	struct test_struct *bb =
		(struct test_struct *)malloc(2 * sizeof(struct test_struct));
	if (bb == NULL) {
		return XDP_PASS;
	}
	bb->a = 42;
	bb->next = bb + 1;
	(bb + 1)->a = 111;
	(bb + 1)->next = NULL;
	bpf_printk("bb: %d\n", bb);
	free(bb);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
