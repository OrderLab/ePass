# Verifier

We design a form of constraint that could describe all types of ebpf verifier rules. The verifier will generate a "constaint set" based on static analysis information (e.g. BTF) and that doesn't need any simulation.

Then this constaint set will be passed to our IR and we will add check for those constaints. Since currently our IR is typeless so we can only use some raw constaint generated from the verifier.

To start with, a simple constaint would be "range constraint", meaning a register (at a specific position) must be within a range.

One opinion, one benefit of designing the raw constraint from is that our runtime-check system will not depend heavily on the current linux verifier and will be portable to other verifiers.

## Roadmap

- [x] Register spilling
- [x] Caller-saved/callee-saved register
- [x] Fix: stack offset should be changed before CG
- [x] VR type & Constant type (inference)
- [x] Translation
- [ ] Add "use result" flag to some functions that may have exceptions
- [ ] Logging
- [ ] Env

# TODO

- More instructions
- bpf-to-bpf calls
- tail calls
