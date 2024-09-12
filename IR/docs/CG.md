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

`REG = ALU v0 v1`

if `v1` is REG and is the same with `dst`, first change it to another register.

Cases of `v0, v1`:

- `REG, CONST` ✅
- `REG, STACK` ✅
- `CONST64, REG` ✅
- `CONST64, CONST` ✅
- `CONST64, STACK` ✅
- `CONST32, REG` ==> PASS
- `CONST32, CONST64` ✅
- `CONST32, CONST32` ==> PASS
- `CONST32, STACK` ✅
- `STACK, CONST` ✅
- `STACK, STACK` ✅
- `STACK, REG` ✅

In summary, these are allowed:

```
REG1 = ALU REG REG2
REG = ALU REG CONST32
REG1 = ALU CONST32 REG2
REG = ALU CONST32 CONST32
REG = ALU STACK CONST32
```

### `call`

PASS.

### `ret`

PASS.

### `ja`

PASS.

### Conditional Jump Instructions

### `phi`

No PHI.

### `assign`

`dst = src`

Cases of `dst, src`:

- `STACK, STACK`
- `STACK, REG`
- `STACK, CONST`
- `REG, CONST`
- `REG, REG`
- `REG, STACK`

## CGIR-II

The form that could be directly mapped to a bytecode instruction.
