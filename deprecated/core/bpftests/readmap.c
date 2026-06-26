#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define HEAP_SIZE 1024

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[HEAP_SIZE]);
} data SEC(".maps");

SEC("xdp")
int prog(void *ctx)
{
	int i = 0;
	char *head = bpf_map_lookup_elem(&data, &i);
	bpf_printk("read: %c\n", head[9]);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
