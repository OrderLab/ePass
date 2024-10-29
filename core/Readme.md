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
- [ ] signed right shift

## TODO

- [ ] Support Configuration: pass config
- [ ] libbpf integration
- [ ] Optimize counter pass
- [ ] Termination point (Exception handler)
- [ ] Exception instruction
- [ ] Helper function to handle the exception
- [ ] Testing the framework using buzzer or similar fuzzing tools
- [ ] Measure the performance

Ask gpt for advise on type I?

runtime write/read wrapper?

## Bugs

### SplitBB operation may not work properly if it's at the top of a BB

### Coalesce has some bugs

## Errors

- Found error with output/mem1.c.nop.o
- Found error with output/ringbuf.c.nop.o
- Found error with output/test_asm.c.o
- Found error with output/mem2.c.nop.o
- Found error with output/test_asm.c.nop.o
- Found error with output/mask.c.nop.o
- Found error with output/memerr1.c.o
- Found error with output/mem1.c.o

Reproduce: `ringbuf.c` enable coalesce will cause some error in CG

# TODO

- More instructions
- bpf-to-bpf calls
- tail calls
