SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int *dynamic_array = malloc(10 * sizeof(int));  // Dynamic memory allocation
    
    dynamic_array[0] = 1;
    
    return XDP_PASS;
}
