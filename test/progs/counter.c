#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("counter")
int prog(struct __sk_buff *skb)
{
    static __u64 count = 0; // Static counter to keep track of packets

    count++;
    bpf_trace_printk("Packet count: %llu\n", count); // Print packet count
    return XDP_PASS; // Allow all packets
}

char _license[] SEC("license") = "GPL";
