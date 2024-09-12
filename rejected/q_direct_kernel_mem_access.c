SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int *kernel_var = (int *)0xffff880001234000;  // Hypothetical kernel memory address
    *kernel_var = 100;
    
    return XDP_PASS;
}
