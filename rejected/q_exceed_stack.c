SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int large_array[200];  // 200 * 4 bytes = 800 bytes, exceeding the 512-byte stack limit
    
    large_array[0] = 1;
    
    return XDP_PASS;
}
