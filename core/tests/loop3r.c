#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_execve")
int prog(void *ctx) {
	for (__u64 i = 0; i < 500; ++i) {
		bpf_ktime_get_ns();
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
