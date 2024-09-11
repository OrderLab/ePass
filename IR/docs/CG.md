# Code Generation

CG Instruction Extension

Dynamic assignment: `ASSIGN`

`dst = src`

`dst` could be stack/reg.

`src` could be reg/const/stack.

INSN value could be VR/non-VR.

## CGIR-I

The stable phase of IR that no longer needs spilling new registers.

## CGIR-II

The form that could be directly mapped to a bytecode instruction.
