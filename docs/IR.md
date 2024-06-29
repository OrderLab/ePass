# bpf IR spec

There are several steps to transform.

## Stack access validation & Map to virtual (stack) registers

Verify stack access.

`r10 - 8*n` ==> Find the largest `n` to get the stack size.

- rn -> VR_n
- [r10 - 8n] -> VSR_n

## BB formation

Form BBs. Get the graph.

We need the pred/succ information of BB.

## Local value numbering

## Global Value Numbering

## Incomplete CFGs

## Remove dead code (Optimization)
