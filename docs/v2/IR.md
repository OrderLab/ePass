# ePass IR v2

The IR's type system is deliberately small. Every SSA value is a 64-bit pattern. Widths, signedness, extension and access sizes live on the **operations**, not on the values. Constants are exact `u64`. Facts such as "is a frame pointer", "is non-negative" or "upper 32 bits are zero" are **derived** by analyses (`epass-core/src/analysis/`). They are never declared, so a pass or an untrusted IR blob can't lie about them. design.md §4 has the reasoning.

## Values

| Syntax | Value |
|---|---|
| `%N` | result of instruction N |
| `42`, `0x2a`, `-1` | constant (exact 64-bit) |
| `%arg1` | entry value of r1 (the context). `%arg2..5` are valid IR (for future subprograms); the lifter never produces them, because r2..r5 are uninitialized at program entry |
| `%fp` | the frame pointer (r10) |
| `undef` | no value. Allowed as a phi input or an unused call argument |

## Operations

Width suffixes are `.32` and `.64`. A 32-bit ALU result is zero-extended to 64 bits, as in eBPF.

| Syntax | Meaning |
|---|---|
| `add\|sub\|mul\|udiv\|sdiv\|umod\|smod\|and\|or\|xor\|shl\|lshr\|ashr.W a, b` | binary ALU; shift counts are masked; division by zero follows RFC 9669 |
| `neg.W a` | negation |
| `zext.F.W a` / `sext.F.W a` | extend the low F bits (8/16/32) to width W |
| `bswap.le\|be\|swap.N a` | byte swap of N bits (16/32/64) |
| `load.u8..u64\|s8..s32 [base+off]` | memory load; `s*` sign-extends (MEMSX) |
| `store.u8..u64 [base+off], v` | memory store |
| `ldsym.KIND imm` | `ld_imm64` with a pseudo source. KIND is one of `map_fd`, `map_value_fd`, `btf_id`, `func`, `map_idx`, `map_value_idx`. A plain 64-bit immediate is just a constant |
| `slotaddr $S+off` / `slotload $S` / `slotstore $S, v` | ePass-owned frame slots, placed below the program's own frame by codegen |
| `call helper#ID(args)` / `call kfunc#BTF:FD(args)` | calls. `call.unknown` marks an unknown signature (userspace only), which passes r1..r5 |
| `ecall#ID(args)` | ePass-internal call (policy `ecall=1`) |
| `opaque 0xRAW(args)` | an instruction ePass doesn't model (atomics, LD_ABS/IND), emitted verbatim on fixed registers |
| `phi [v, bbN], ...` | SSA phi, one input per predecessor |
| `br bbN` | jump |
| `condbr.W.COND a, b, bbT, bbF` | COND is one of `eq`, `ne`, `ugt`, `uge`, `ult`, `ule`, `sgt`, `sge`, `slt`, `sle`, `set` (JSET) |
| `ret v` | exit with r0 = v |
| `throw` | abort; lowered by `lower_throw` |
| `poison IMM` | a libbpf poison call (failed CO-RE relocation), kept verbatim |

## Text format (`.epir`)

```text
; epir v2
func main {
bb0:
  br bb1
bb1: ; preds bb0
  %0 = load.u64 [%arg1+0]
  %1 = add.64 %0, 1
  condbr.64.ult %1, 10, bb2, bb3
bb2: ; preds bb1
  store.u64 [%fp-8], %1
  ret 0
bb3: ; preds bb1
  ret %1
}
```

Instructions and blocks are renumbered densely when printed. `;` starts a comment. The parser (feature `text`, userspace only) accepts forward references, which phis in loops need, and the result is validated like any IR.

## Binary format (blob)

The kernel only accepts the blob, never text. `epasstool convert` converts in both directions. The layout:

- 32-byte header (`EPIR`, version 1);
- per function, a 32-byte header;
- fixed-size records: slots 8 B, blocks 8 B, instructions 32 B, operands 16 B, in strict order.

The decoder rejects anything out of order or out of range. Resource errors (OOM, limits) are reported as such, never as "invalid IR". `epass-core/src/bin.rs` documents every field.

## Validation (the security boundary)

`ir::verify::verify` checks:

- operand kinds per opcode;
- widths and sizes;
- phi arity against predecessors;
- terminators;
- that definitions dominate their uses (including phi inputs at the end of the predecessor);
- slot bounds and the 512-byte frame;
- the ecall permission.

IR from a loader is untrusted. It's validated after decoding and again after every pass in debug builds (gopt `verify_each`), and always before codegen.
