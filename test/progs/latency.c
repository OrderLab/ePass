#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("latency")
int prog(void *ctx)
{
    __u64 start_time = bpf_ktime_get_ns(); // Get start time

    // Simulate some processing here
    bpf_trace_printk("Processing...\n");

    __u64 end_time = bpf_ktime_get_ns(); // Get end time
    __u64 latency = end_time - start_time; // Calculate latency

    bpf_trace_printk("Latency: %llu ns\n", latency); // Print latency
    return 0;
}

char _license[] SEC("license") = "GPL";
