#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	int arr[10] = {0};
    for(int i = 0; i < 10; ++i) {
        arr[i] = i;
    }
    int id = bpf_ktime_get_ns() %10;
    if (id < 2 || id > 8) {
        return 0;
    }
	bpf_printk("%d: %d\n", id, arr[id]);
	// 1535866789

	return 0;
}

char _license[] SEC("license") = "GPL";
