#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* BPF Hash Map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} my_map SEC(".maps");

SEC("hashmap")
int prog(struct __sk_buff *skb)
{
    __u32 key = 1;
    __u64 *value;

    value = bpf_map_lookup_elem(&my_map, &key);
    if (value) {
        (*value)++;
        bpf_trace_printk("Value for key %u: %llu\n", key, *value);
    } else {
        __u64 initial_value = 1;
        bpf_map_update_elem(&my_map, &key, &initial_value, BPF_ANY);
        bpf_trace_printk("Key %u initialized with value 1\n", key);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
