# IR Type System

Design goal: we want the type system be as minimal as possible BUT enough to generate correct code.

It's IMPOSSIBLE to generate correct code without type information.

Here "type" information is about the size of a data which assembly language cares about, not about any other real types in C.

Correctness:

- The behavior of original program doesn't change.

We do not change the OP type of ALU instructions in the original program.

All ALU instructions have 2 mode: 32 bits/64 bits.

```
a = add x y
b = add64 x y
```

It's difficult to say what is correct, we could let users specify the type when doing ALU opetations.

## Constant Type

There is only one type: `64`.

All other size could be encoded into this `64` data.

## Load/Store/Alloc

`Store` & `Load` use the size defined in alloc.

## Loadraw/Storeraw

`Loadraw` provides the address and size directly.

`Storeraw` provides the size and address, along with a value.
