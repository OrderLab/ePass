SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int (*func_ptr)(int) = some_function;
    int result = func_ptr(5);  // Calling a function through a pointer
    
    return result;
}

int some_function(int x) {
    return x * 2;
}
