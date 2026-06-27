# Rust Core Architecture

The Rust core (`core-rs/epass-ir`) is the active ePass compiler library. It is a
userspace-only rewrite of the old C core and is designed to be embedded by
CLIs, tests, and patched libbpf.

## Pipeline

```text
BpfInsn[]
  -> lift
  -> Function (SSA IR)
  -> PassManager
  -> codegen prep
  -> liveness/interference
  -> register allocation + spilling
  -> SSA-out
  -> normalize/emit
  -> BpfInsn[]
```

## IR model

The IR uses stable arena indices instead of raw pointers:

- `Function` owns instruction and block arenas.
- `InsnId` identifies an instruction.
- `BbId` identifies a basic block.
- Removed instructions are tombstoned rather than moving arena entries.
- Def-use lists are maintained by helper methods and checked after passes.

Important types:

```rust
Function
BasicBlock
Insn
InsnKind
Value
InsnId
BbId
```

Pseudo values:

- `func.sp` is the stack/frame pointer pseudo (`R10`).
- `func.args[0..5]` are function argument pseudos (`R1..R5`).

## Building IR

Use `IrBuilder` for pass code whenever possible:

```rust
let mut b = IrBuilder::before_terminator(func, bb);
let x = b.add(AluOp::Alu64, lhs, rhs);
b.ret(Value::Insn(x));
```

`IrBuilder` updates def-use automatically.

Low-level construction remains available:

```rust
let id = func.create_insn(bb, InsnKind::Assign, InsertPos::Back);
func.add_value_operand(id, value);
```

## CFG utilities

`Function` exposes helpers for common CFG edits:

```rust
terminator(bb)
is_terminated(bb)
successor_targets(bb)
set_ja_target(ja, target)
set_cond_targets(cond, fallthrough, taken)
replace_successor(from, old_to, new_to)
split_edge(from, to)
split_block_before(insn)
split_block_after(insn)
create_ret_block(value)
create_throw_block()
```

`split_edge` also relabels phi predecessors in the successor block.

## Pass framework

Passes implement one trait:

```rust
trait Pass {
    fn name(&self) -> &str;
    fn enabled_by_default(&self) -> bool;
    fn allow_disable(&self) -> bool;
    fn init(&mut self, arg: Option<&str>) -> Result<()>;
    fn register_pass(&self, order: Vec<String>) -> Result<Vec<String>>;
    fn run(&self, env: &mut Env, func: &mut Function) -> Result<()>;
}
```

The pass manager:

1. parses `--popt`;
2. enables/disables/configures passes;
3. lets enabled passes order themselves;
4. verifies each pass only moves/inserts/removes itself;
5. runs passes with `postprocess` after each pass.

See [PASS_MANAGER.md](PASS_MANAGER.md).

## Postprocess after every pass

After each pass:

```text
recompute successors
cfg::finalize
remove unreachable edges
prune dead phi inputs
prog_check
```

`prog_check` validates:

- branch successor structure;
- conditional fallthrough layout;
- phi placement;
- phi inputs matching predecessor blocks;
- def-use consistency.

## IR text format

`.epir` is a parseable debugging format. See [IR_TEXT.md](IR_TEXT.md).

Library APIs:

```rust
epass_ir::dump_ir(&func)
epass_ir::load_ir_str(&text)
epass_ir::load_ir_file(path)
```

Pipeline option:

```bash
--gopt load_ir=/tmp/prog.epir
```

Dump pass option:

```bash
--popt 'dump_ir(/tmp/prog.epir)'
```

## Code generation

The code generator performs:

- call/argument lowering to physical register copies;
- array/constant spill preparation;
- liveness and interference construction;
- pre-spilling of oversized cliques;
- greedy coloring;
- post-spill fallback if coloring fails on a non-chordal graph;
- copy coalescing;
- phi removal / SSA-out;
- BPF instruction emission.

The post-spill fallback is required because ePass adds register constraints that
can make the interference graph non-chordal even though pure SSA interference
graphs are chordal.
