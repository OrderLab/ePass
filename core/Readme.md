# Verifier

We design a form of constraint that could describe all types of ebpf verifier rules. The verifier will generate a "constraint set" based on static analysis information (e.g. BTF) and that doesn't need any simulation.

Then this constraint set will be passed to our IR and we will add check for those constraints. Since currently our IR is typeless so we can only use some raw constraint generated from the verifier.

To start with, a simple constraint would be "range constraint", meaning a register (at a specific position) must be within a range.

One opinion, one benefit of designing the raw constraint from is that our runtime-check system will not depend heavily on the current linux verifier and will be portable to other verifiers.

## Future work

Rewrite Normalization. Plain the IR.

Just store the allocated position in value. Not track users. No references.

All VRs are changed to Real Registers.

## Bugs

### SplitBB operation may not work properly if it's at the top of a BB

Resolved.

### Coalesce has some bugs

Found root cause: you may not directly remove instructions like r1 = r1.

## Errors

Reproduce: `ringbuf.c` enable coalesce will cause some error in CG

Raw libbpf library loader doesn't change the "imm" value when calling the `callback_fn`. It doesn't support calling it after changing the resources.

# TODO

- bpf-to-bpf calls
