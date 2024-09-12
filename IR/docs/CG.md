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

`dst = loadraw vt addr_val`

Cases of `dst, addr_val`:

- `REG, REG` ==> PASS
- `*, CONST` ==> TODO
- `STACK, REG` ==>
    R0 = loadraw vt addr_val
    dst = R0
- `STACK, STACK` ==>
    R0 = addr_val
    R0 = loadraw vt R0
    dst = R0
- `REG, STACK` ==>
    R0 = addr_val
    dst = loadraw vt R0

In summary, this form is valid:

```
REG = loadraw vt REG
```

### `loadrawextra`

`dst = loadrawextra imm_extra_type imm64`

- `STACK` ==>
    R0 = loadrawextra imm_extra_type imm64
    dst = R0

Allowed: `REG = ...`.

### ALU Binary Instructions

`dst = ALU v0 v1`

If dst is STACK, we first change it to REG.

In summary, these are allowed:

```
REG = ALU REG REG
REG = ALU REG CONST32
REG = ALU CONST32 REG
REG = ALU CONST32 CONST32
```

### `call`

### `ret`

### `ja`

### Conditional Jump Instructions

### `phi`

## CGIR-II

The form that could be directly mapped to a bytecode instruction.
