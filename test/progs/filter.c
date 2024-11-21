#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("filter")
int prog(struct __sk_buff *skb)
{
    // Filter packets based on their length
    if (skb->len < 100) {
        return XDP_DROP; // Drop packets smaller than 100 bytes
    }
    return XDP_PASS; // Pass other packets
}

char _license[] SEC("license") = "GPL";
