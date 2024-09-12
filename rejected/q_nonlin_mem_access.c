SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int arr[5] = {1, 2, 3, 4, 5};
    
    // Non-linear memory access, verifier may reject this as unsafe
    return arr[(ctx->data % 5)];
}
