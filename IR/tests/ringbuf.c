#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256);
} rb SEC(".maps");

SEC("xdp")
int prog(void *ctx)
{
	int *x = bpf_ringbuf_reserve(&rb, sizeof(int), 0);
    if(!x) return XDP_DROP;

    bpf_ringbuf_discard(x, 0);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
