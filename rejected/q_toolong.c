SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int sum = 0;

    // Simple loop that produces too many instructions after unrolling
    for (int i = 0; i < 100000; i++) {
        sum += i;
    }

    return sum;
}
