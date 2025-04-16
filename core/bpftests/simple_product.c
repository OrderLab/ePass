#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define N 3
#define IDX(i, j) ((i) * N + (j))

SEC("xdp")
int prog(struct xdp_md *ctx) {
    int A[N * N];

    int B[N * N] ;

    int C[N * N] = {0};


    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            A[IDX(i, j)] = bpf_ktime_get_ns() % 10;
            B[IDX(i, j)] = bpf_ktime_get_ns() % 10;
        }
    }
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            for (int k = 0; k < N; k++) {
                C[IDX(i, j)] += A[IDX(i, k)] * B[IDX(k, j)];
            }
        }
    }

    // Verification step (can’t return string or print in eBPF)
    int result = 0;
    for (int i = 0; i < N * N; i++) {
        result += C[i];
    }
    bpf_printk("Result: %d\n", result);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
