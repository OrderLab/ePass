SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int arr[5] = {1, 2, 3, 4, 5};
    int index = ctx->data;  // Pretend this is sanitized correctly

    // Verifier cannot guarantee the safety of this access
    return arr[index % 5];
}
