SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int arr[5];
    int value = arr[0];  // Reading uninitialized stack memory

    return value;
}
