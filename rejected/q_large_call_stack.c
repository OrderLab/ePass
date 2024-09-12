SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int a = 5, b = 10, c = 15;
    
    // Complex control flow due to multiple nested conditions
    if (a > 0) {
        if (b > 0) {
            if (c > 0) {
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}
