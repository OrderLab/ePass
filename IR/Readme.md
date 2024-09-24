# Verifier

We design a form of constraint that could describe all types of ebpf verifier rules. The verifier will generate a "constraint set" based on static analysis information (e.g. BTF) and that doesn't need any simulation.

Then this constraint set will be passed to our IR and we will add check for those constraints. Since currently our IR is typeless so we can only use some raw constraint generated from the verifier.

To start with, a simple constraint would be "range constraint", meaning a register (at a specific position) must be within a range.

One opinion, one benefit of designing the raw constraint from is that our runtime-check system will not depend heavily on the current linux verifier and will be portable to other verifiers.

## Roadmap

- [x] Register spilling
- [x] Caller-saved/callee-saved register
- [x] Fix: stack offset should be changed before CG
- [x] VR type & Constant type (inference)
- [x] Translation
- [x] Logging
- [x] Env
- [x] If ALU ops (including cond jmp) use 64 bits const, load it to register
- [x] Switch back for ALU spill
- [x] Test adding counter & print some result
- [x] CGIR-I and CGIR-II formalization
- [x] CONSTOFF: add r10 const optimization
- [x] Fix: mask

## Bugs

- `erase_insn_cg` Not working in the normalization. Should spilling use `safe` list iterations?

# TODO

- More instructions
- bpf-to-bpf calls
- tail calls
