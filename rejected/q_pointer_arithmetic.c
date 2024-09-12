SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    char *data = (char *)(long)ctx->data;
    char *data_end = (char *)(long)ctx->data_end;
    
    // Pointer arithmetic that is technically correct
    data += 4;
    if (data + 4 > data_end) {
        return XDP_DROP;
    }
    
    return XDP_PASS;
}
