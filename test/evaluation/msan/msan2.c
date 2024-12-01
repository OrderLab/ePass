#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx)
{
    // char s[] = "asf\n";
    // bpf_printk("%s\n",s);
    int k = bpf_ktime_get_ns() % 2;
    int a[5];
    a[0] = k;
    a[1] = k - 1;
    if(k<0 || k >2){
        return 0;
    }
    bpf_printk("%d\n",a[k]);
	return 0;
}

char _license[] SEC("license") = "GPL";
