/**
    Exceeding jump limit.

    "I attempted using nested BPF maps, but the limitation seems to be the loop through the array, not the array itself."

    "A cumbersome workaround has been to use the array elements as keys in a hashmap, but this approach is neither scalable nor maintainable. Is there a more elegant solution to this problem that avoids excessive looping while complying with the verifier's restrictions?"

    "Even if you can fix the verifier limitation your program will be slow which might effect packet processing speed and throughput."

    https://stackoverflow.com/questions/77444624/how-to-design-ebpf-map-for-large-data-structures-without-exceeding-jump-complexi
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct array_of_elements {
    /*some data, around 9 members, all necessary to perform a scan on TC ingress*/
};

struct data_structure {
    struct array_of_elements arr[600];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct data_structure);
} internal_map SEC(".maps");

SEC("xdp")
int prog(struct xdp_md *ctx) {
    for (int i = 0; i < 600; i++) {
        if (lookup_result->arr[i].present) { /* some processing */
        }
    }
}
