# Existing Work Around for Loops

## Discussion about implementing a different approach to BPF loops

https://lwn.net/Articles/877062/

## Loop Callback

`bpf_loop`

## Iterate over a map

`bpf_for_each_map_elem`

- https://stackoverflow.com/questions/73655533/loop-through-all-elements-in-bpf-map-type-hash

# Checking bounds

Many posts are about forgetting to check bounds.

- https://stackoverflow.com/questions/74531552/bpf-verification-fails-due-to-register-offset
- https://stackoverflow.com/questions/61702223/bpf-verifier-rejects-code-invalid-bpf-context-access
- https://stackoverflow.com/questions/68752893/how-to-read-understand-the-bpf-kernel-verifier-analysis-to-debug-the-error
- https://stackoverflow.com/questions/56141993/ebpf-newbie-need-help-facing-an-error-while-loading-a-ebf-code/56475180#56475180

Falco writes many helper functions and macros to handle these problems, for example:

```c
#define SAFE_ARG_NUMBER(x) x & (PPM_MAX_EVENT_PARAMS - 1)
```

## LLVM compiler

LLVM tends to generate code that verifier doesn't understand. People write ASM code directly to pass that.

# Verifier Pitfalls

https://github.com/cilium/cilium/issues/5130