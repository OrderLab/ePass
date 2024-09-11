# Code Generation

## Relationship

Value := INSN | Const | Stackptr (REG)

INSN := VR | Pre-colored Register (PCR) (REG)

VR := REG | STACK

## CG Instruction Extension

Dynamic assignment: `ASSIGN`

`dst = src`

`dst` could be stack/reg.

`src` could be reg/const/stack.

INSN value could be VR or PCR.

## CGIR-I

The stable phase of IR that no longer needs spilling new registers.

### `alloc`

Nothing to do. This is a pseudo instruction.

OK.

### `store`

`store v0 v1`

Rewrite to `v0 = v1`. (with vt info)

### `load`

`dst = load v0`

Rewrite to `dst = v0`. (with vt info)

### `storeraw`

`storeraw vt addr_val v0`

Case of `addr_val, v0`:

- `STACK, STACK` ==> TODO
- `*, CONST64` ==> TODO
- `STACK, REG/CONST32` ==>
    Rx = addr_val
    storeraw vt Rx v0
- `REG, STACK` ==>
    Rx = v0
    storeraw vt addr_val Rx
- `REG, REG` ==> PASS
- `REG, CONST32` ==> PASS
- `CONST, *` ==> TODO

In summary, CGIR-I have this form:

```
storeraw vt REG REG
storeraw vt REG CONST32
```

### `loadraw`

`dst = loadraw vr_type addr_val`

Cases of `dst, addr_val`:

- `REG, REG` ==> PASS
- `*, CONST` ==> TODO
- `STACK, REG` ==>
    R0 = loadraw vr_type addr_val
    dst = R0
- `STACK, STACK` ==>
    R0 = addr_val
    R0 = loadraw vr_type R0
    dst = R0
- `REG, STACK` ==>
    R0 = addr_val
    dst = loadraw vr_type R0

### `loadrawextra`

### ALU Binary Instructions

### `call`

### `ret`

### `ja`

### Conditional Jump Instructions

### `phi`

## CGIR-II

The form that could be directly mapped to a bytecode instruction.
