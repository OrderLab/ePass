SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int sum = 0;

    // Multiple helper function calls, verifier may reject this as "too complex"
    for (int i = 0; i < 10; i++) {
        sum += bpf_ktime_get_ns();  // Call to helper function
    }

    return sum;
}
