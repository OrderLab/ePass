#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct value {
    int index;
    char flags[100];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32);
    __type(key, __u8); 
    __type(value, struct value); 
} output_map SEC(".maps");

static __always_inline void store_flags(struct value *value){
    if (value->index < sizeof(value->flags)){
        value->flags[value->index] = ',';
        value->index++;
    }
    
    if (value->index < sizeof(value->flags)){
        value->flags[value->index] = ',';
        value->index++;
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tracepoint(void *ctx) {
     __u8 key = 1;
    struct value *value;
    value = bpf_map_lookup_elem(&output_map, &key);

    if (value == NULL){
        struct value initial_value = {
            .index = 1,
            .flags = ","
        };
        bpf_map_update_elem(&output_map, &key, &initial_value, BPF_NOEXIST);
    } else {
        store_flags(value);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
