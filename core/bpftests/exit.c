#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int prog(void *ctx)
{
	int err = 0;
    int j = bpf_ktime_get_ns() % 10;
    if (j > 5) {
        err = 3;
        goto end;
    }
    bpf_printk("%d\n", j);
end:
	return err;
}

char _license[] SEC("license") = "GPL";
