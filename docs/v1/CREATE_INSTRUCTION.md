# Creating IR Instructions in `core-rs`

The old C core exposed many `create_*_insn` constructors. In the Rust core, use
`IrBuilder` for pass code and `Function` primitives for low-level cases.

## Preferred API: `IrBuilder`

```rust
use epass_ir::ir::{IrBuilder, InsertPos, Value, AluOp, BinOp, VrType};

let mut b = IrBuilder::before_terminator(func, bb);
let tmp = b.add(AluOp::Alu64, lhs, Value::const64(1));
b.store_raw(VrType::B64, base, -8, Value::Insn(tmp));
```

The builder:

- creates the instruction;
- inserts it at the configured insertion point;
- fills opcode-specific fields;
- updates def-use chains;
- returns the new `InsnId`.

## Insertion points

```rust
IrBuilder::at_bb(func, bb, InsertPos::Back)
IrBuilder::at_end(func, bb)
IrBuilder::at_start(func, bb)
IrBuilder::before_terminator(func, bb)
IrBuilder::after_phi(func, bb)

IrBuilder::at_insn(func, anchor, InsertPos::Front)
IrBuilder::before(func, anchor)
IrBuilder::after(func, anchor)
```

## Supported constructors

Allocation:

```rust
b.alloc(VrType::B64)
b.alloc_array(VrType::B8, 32)
```

Memory:

```rust
b.store(slot, value)
b.load(slot)
b.store_raw(VrType::B32, base, offset, value)
b.load_raw(VrType::B64, base, offset)
```

Immediates:

```rust
b.load_imm_extra(LoadImmExtra::Imm64, 42)
```

ALU:

```rust
b.bin(BinOp::Add, AluOp::Alu64, lhs, rhs)
b.add(...)
b.sub(...)
b.mul(...)
b.div(...)
b.and(...)
b.or(...)
b.xor(...)
b.lsh(...)
b.rsh(...)
b.arsh(...)
b.modulo(...)
b.neg(AluOp::Alu64, value)
b.end(EndKind::ToBe, 32, value)
```

Calls and returns:

```rust
b.call(6, [arg0, arg1])?
b.ecall([arg0])?
b.ret(value)
b.throw()
```

Branches:

```rust
b.ja(target)
b.cond_jmp(Cond::Eq, AluOp::Alu64, lhs, rhs, fallthrough, taken)
b.jeq(...)
b.jne(...)
b.jgt(...)
b.jge(...)
b.jlt(...)
b.jle(...)
b.jsgt(...)
b.jsge(...)
b.jslt(...)
b.jsle(...)
```

Phi and copies:

```rust
b.phi_entries([(value1, pred1), (value2, pred2)])
b.assign(value)
```

Misc:

```rust
b.get_elem_ptr(index, array)
b.reg(reg_id)          // mostly for codegen/tests
b.function_arg(arg_id) // mostly for specialized tests
```

## Low-level API

Use this only when a builder method is not appropriate:

```rust
let id = func.create_insn(bb, InsnKind::Assign, InsertPos::Back);
func.add_value_operand(id, value);
```

Do **not** push operands manually unless you also maintain def-use:

```rust
// Avoid this in passes:
func.insn_mut(id).values.push(value); // missing add_use!
```

If you must manipulate operands manually, use:

```rust
func.add_value_operand(id, value)
func.add_phi_operand(phi, value, pred_bb)
func.clear_values(id)
func.replace_value_in(user, old, new)
func.replace_all_uses(def, replacement)
```

`prog_check` validates def-use after each pass and will catch many mistakes.

## CFG helpers

For block and branch manipulation, use `Function` CFG utilities:

```rust
func.terminator(bb)
func.successor_targets(bb)
func.set_ja_target(ja, target)?
func.set_cond_targets(cond, fallthrough, taken)?
func.replace_successor(from, old_to, new_to)?
func.split_edge(from, to)?
func.split_block_before(insn)?
func.split_block_after(insn)?
func.create_ret_block(value)
func.create_throw_block()
```

`split_edge` relabels phi inputs in the successor block and is the safest way to
insert instrumentation on an existing CFG edge.
