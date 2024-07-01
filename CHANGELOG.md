# 1 July

Continue to write code on BB gen and SSA pass to generate IR.

# 28 June

Writing basic code for IR and BB gen.

# 27 June

Searching for related projects (x86 to LLVM IR decompiler).

# 26 June

Reading SSA literatures.

# 25 June

Designing IR.

# 24 June

Found an issue: https://github.com/solana-labs/solana/issues/20323.

We could use runtime optimization strategy (profile based optimization, my 583 project was doing profile-based compiler optimization).

`bpf_prog*` --> Verifier --> JIT

==>

`bpf_prog*` --> Verifier --> **To SSA** --> Optimization/Insert runtime code --> **Register alloc, back to bytecode** --> JIT

## Profiling

Insert profiling code like LLVM profiler, get the hot path ==> Try verify hot path and remove check code on hot path.

Read JIT code.

# 21 June

Design the basic architecture.

![](docs/architecture.png)

Transform eBPF prog to SSA form at runtime to help analyze/optimize during runtime.

# 20 June

Read verifier/JIT source code.

# 19 June - Meeting

Motivation study and analysis

# 16 June

Initialize kernel tree to 6.6.34.
