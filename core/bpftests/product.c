#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define N 5

SEC("xdp")
int prog(void *ctx){
    int i = 0, j = 0;
    int mat_a[N][N], mat_b[N][N], result[N][N];
    for (i = 0; i < N; ++i) {
        for (j = 0; j < N; ++j) {
            mat_a[i][j] = (i * (i+1)+ j * (j+1)) & ((1 << 16) - 1);
            mat_b[i][j] = i & ((1 << 16) - 1);
            result[i][j] = 0;
        }
    }

    //multiply
    for (i = 0; i < N; ++i) {
        for (j = 0; j < N; ++j) {
            for (int k = 0; k < N; ++k) {
                result[i][j] += mat_a[j][i] * mat_b[i][k];
            }
        }
    }

    long long sum = 0;
    for (i = 0; i < N; ++i) {
        for (j = 0; j < N; ++j) {
            sum += result[i][j];
        }
    }
    bpf_printk("sum is %lld\n", sum);
    // 5250
    return 0;
}

char _license[] SEC("license") = "GPL";
