SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int arr[10];
    
    // Verifier rejects arbitrary memory access
    for (int i = 0; i < 10;
        arr[i] = i * 2;
    }

    return XDP_PASS;
}
