# Summary

Most rejected eBPF programs could be divided into these categories:

1. LLVM generates bytecode that is problematic and couldn't be understood by the verifier.
2. Programmers forget to check bounds.
3. Programs exceed maximum instruction limit.
4. Verifier cannot infer the constraints for loops.
5. Verifier bugs.
6. Cost too much time for verifier to analyze.

For 1, they (Cilium) directly write assembly code. ==> Assembly code is hard to understood and maintain.

For 2, they often use "mask" or add extra check code. ==> Some check code is redundant.

For 3, they use tail calls to divide the programs. ==> Tail calls have overhead.

For 4, they manually add enforce some conditions to pass the verifier. ==> Those conditions are redundant, code unclear, less readable.
