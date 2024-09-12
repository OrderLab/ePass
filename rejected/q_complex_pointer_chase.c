SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    struct data_struct {
        int a;
        int b;
        int c;
    } *ptr;
    
    ptr = (struct data_struct *)(ctx->data);
    
    // Multiple pointer dereferences can make the verifier reject the code
    int value = ptr->a + ptr->b + ptr->c;
    
    return value;
}
