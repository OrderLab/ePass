SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int i = 0;
    int data[] = {1, 2, 3, 4, 5};
    
    // This will be rejected because the loop bound is variable
    while (i < 5) {
        i++;
    }
    
    return XDP_PASS;
}
