# bpf IR spec

There are several steps to transform.

## Stack access validation & Map to virtual (stack) registers

Verify stack access.

Memory access: not allowed to have `r10` + a non-constant address.

Stack address: `0x123s` means `r10 - 0x123`.

`allocP`: allocate a register at a given position.

```
r1 = 0x6968
*(u16 *)(r10 - 0x4) = r1
r1 = 0x0
*(u8 *)(r10 - 0x2) = r1
r1 = r10
r1 += -0x4
r2 = 0x3
call 0x6
```

==>

```
%0 = 0x6968
%1 = allocP 2, 0x4s
store 2, %1, %0
%2 = 0x0
store 1, 0x2s, %2
%3 = 0x0s
%4 = add %3, -0x4
%5 = 0x3
call 0x6(%4, %5)
```

## BB formation

Form BBs. Get the graph.

We need the pred/succ information of BB.

## Local value numbering

## Global Value Numbering

## Incomplete CFGs

## Remove dead code (Optimization)
