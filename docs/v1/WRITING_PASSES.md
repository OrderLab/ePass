# Writing Passes for `core-rs`

Passes transform or analyze `Function` IR. This guide describes the Rust pass API,
pass options, ordering, and safe IR construction helpers.

## Pass trait

Implement `epass_ir::Pass`:

```rust
use epass_ir::{Env, Result, Pass};
use epass_ir::ir::Function;

#[derive(Default)]
struct MyPass {
    enabled_feature: bool,
}

impl Pass for MyPass {
    fn name(&self) -> &str { "my_pass" }

    fn enabled_by_default(&self) -> bool { false }
    fn allow_disable(&self) -> bool { true }

    fn init(&mut self, arg: Option<&str>) -> Result<()> {
        if let Some(arg) = arg {
            self.enabled_feature = arg.contains("feature=1");
        }
        Ok(())
    }

    fn register_pass(&self, mut order: Vec<String>) -> Result<Vec<String>> {
        // Move this pass after const_prop if both are enabled.
        let name = self.name();
        if let Some(pos) = order.iter().position(|p| p == name) {
            let own = order.remove(pos);
            if let Some(cp) = order.iter().position(|p| p == "const_prop") {
                order.insert(cp + 1, own);
            } else {
                order.push(own);
            }
        }
        Ok(order)
    }

    fn run(&self, env: &mut Env, func: &mut Function) -> Result<()> {
        // mutate/analyze func here
        Ok(())
    }
}
```

Options are parsed in `init` before any IR is mutated. `run` receives a configured
pass object.

## Pass options (`--popt`)

Syntax:

```text
pass
pass(arg)
!pass
```

Examples:

```bash
--popt 'dump_ir(/tmp/lift.epir)'
--popt '!const_prop'
--popt 'optimize_ir(no_dead_elim)'
```

Pass options do not specify order. Each pass decides its own position in
`register_pass`.

## Ordering rules

`register_pass` receives the current ordered pass-name list and returns a new
list. The pass manager verifies that the pass only changes entries with its own
name. It may move, insert, or remove itself; it may not reorder or edit other
passes.

The manager iterates registration until stable, with a limit to detect cycles.

## Postprocess after every pass

After every pass run, the manager performs:

```text
recompute CFG successors
cfg::finalize
remove unreachable edges
prune dead phi inputs
prog_check
```

This means a pass can rewrite branch targets and rely on postprocess to refresh
CFG metadata and validate def-use/phis.

## Safe IR construction

Prefer `IrBuilder`:

```rust
use epass_ir::ir::{IrBuilder, AluOp, Value};

let mut b = IrBuilder::before_terminator(func, bb);
let x = b.add(AluOp::Alu64, lhs, Value::const64(1));
b.ret(Value::Insn(x));
```

`IrBuilder` updates def-use automatically.

If using low-level APIs, maintain def-use with helpers:

```rust
let id = func.create_insn(bb, InsnKind::Assign, InsertPos::Back);
func.add_value_operand(id, value);
```

Do not push to `insn.values` directly unless you also update users.

## CFG helpers

Use `Function` helpers for common CFG edits:

```rust
func.split_edge(from, to)?;
func.split_block_before(insn)?;
func.replace_successor(from, old_to, new_to)?;
func.set_ja_target(ja, target)?;
func.set_cond_targets(cond, fallthrough, taken)?;
func.create_ret_block(Value::const64(1));
```

`split_edge` updates phi predecessor labels and is the safest way to insert a
block on an existing edge.

## Debugging passes

Enable IR dumps:

```bash
epasstool read -P --popt 'dump_ir(/tmp/lift.epir)' prog.o
```

Or call from pass code:

```rust
let text = epass_ir::ir::text::dump_function(func);
std::fs::write("/tmp/after-my-pass.epir", text)?;
```

Load IR directly:

```bash
epasstool read --gopt load_ir=/tmp/lift.epir dummy.txt
```

## Checklist

Before adding a new pass:

1. Implement `Pass` with a stable `name()`.
2. Decide `enabled_by_default` and `allow_disable`.
3. Parse pass-specific options in `init`.
4. Define order in `register_pass`.
5. Use `IrBuilder`/CFG helpers for mutations.
6. Add tests.
7. Run `cargo test --release`.
