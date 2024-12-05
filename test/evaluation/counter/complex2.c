/**
    Too much time to analysis

    https://stackoverflow.com/questions/78603028/bpf-program-is-too-large-processed-1000001-insn

 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_BUF_LEN 1000

SEC("tracepoint/syscalls/sys_enter_getppid")
int prog(void *ctx)
{
    char fmts[100] = "helhlo hhh world";
    char msgs[100] = {0};
    int i = 0;
    char *fmt = fmts;
    char *msg = msgs;
    while (i < MAX_BUF_LEN) {
        if (*fmt == '\0')
            break;
        if (*fmt == 'h') {
            fmt++;
            i++;
            continue;
        }

        i++;
        *msg++ = *fmt++;
    }

	return 0;
}

char _license[] SEC("license") = "GPL";
