# Writing a pass (v2)

Passes live in `core-rs/epass-core/src/passes/`. The same code runs in the kernel, so it follows the core's rules:

- **No panics.** Clippy denies `unwrap`, `expect`, indexing, `panic!` and `unreachable!` in epass-core. Use the checked accessors (`f.op(i)?`, `slice.get(k)`) and return `Error::internal(..)` for "impossible" states.
- **Fallible allocation only.** Use `FVec`, `IdxVec` and `BitSet` from `crate::mem` with `?`. No `alloc`/`std` collections.
- **No recursion proportional to the input.** Use worklists; the kernel stack is 16 KB.
- **Call `cx.ctx.tick()?` in every loop over instructions or blocks.** That's how the kernel can reschedule, enforce the time limit or stop on a fatal signal.
- **Derive facts, never assume them.** Use `crate::analysis`:
  - `Cfg`, `DomTree`;
  - `Magnitude` (significant bits, counted-loop bounds);
  - `UpperZero`;
  - `Classes`;
  - `Provenance` (frame pointers).

## Descriptor

```rust
pub const INFO: PassInfo = PassInfo {
    name: "mul_to_shl",
    phase: Phase::Optimize,          // Canonicalize | Optimize | Instrument | Finalize
    after: &["const_prop"],          // ordering constraints within the phase
    before: &["dce"],
    default_on: true,                // runs unless the loader says !mul_to_shl
    user_controllable: true,         // loaders may enable/disable/configure it
    mandatory: false,                // Finalize lowerings that must always run
    check_args: no_args,             // validates `mul_to_shl(args)` at pipeline build
    run,
};
```

Register it in two places:

- add `pub mod mul_to_shl;` to `passes/mod.rs`;
- add `crate::passes::mul_to_shl::INFO` to `pm::REGISTRY`.

The order is one topological sort of the registry: by phase first, then the constraints, then registration order. It never depends on the program or the options, and `registry_order` rejects cycles.

## Body

```rust
fn run<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>, _args: Option<&str>) -> Result<()> {
    let cfg = Cfg::compute(f, cx.ctx)?;
    // Collect first, then edit: the walk must not see half-edited IR.
    let mut todo: FVec<'h, (InsnId, u64)> = FVec::new(f.heap());
    for &b in cfg.rpo() {
        for i in f.iter_block(b) {
            cx.ctx.tick()?;
            if let Op::Bin { op: BinOp::Mul, w } = f.op(i)? {
                if let Value::Const(c) = f.operand(i, 1)? {
                    if c.is_power_of_two() && c < (1u64 << (w.bits() - 1)) {
                        todo.push((i, c.trailing_zeros() as u64))?;
                    }
                }
            }
        }
    }
    for &(i, k) in todo.iter() {
        let Op::Bin { w, .. } = f.op(i)? else { continue };
        let x = f.operand(i, 0)?;                 // read operands at edit time
        let s = f.insert(At::Before(i), Op::Bin { op: BinOp::Shl, w }, &[x, Value::Const(k)])?;
        f.replace_all_uses(i, Value::Insn(s))?;
        f.remove(i)?;                             // only once nothing uses it
    }
    Ok(())
}
```

Things to know about the edit API (`ir/func.rs`):

- **Operands and uses.**
  - `operand(i, k)` / `operands(i)` read operands.
  - `set_operand(i, k, v)` changes one.
  - `uses(def)` iterates the exact per-operand use list.
  - `replace_all_uses(def, v)` rewrites every use.
- **Inserting and moving.**
  - `insert(At, op, operands)` places a new instruction. `At` is one of `End`, `BeforeTerminator`, `AfterPhis`, `Before(i)` or `After(i)`.
  - `insert_phi(b)` / `add_phi_input(phi, v, pred)` build phis.
  - `move_insn` moves an instruction.
  - `remove(i)` requires that `i` has no uses.
- **Control flow.**
  - `set_terminator` / `retarget` / `split_edge` / `remove_block` edit it.
  - Successors are derived from terminators, and predecessors are kept up to date for you.
  - After removing an edge, fix the target's phis with `remove_phi_input` (`ir/cleanup.rs` has helpers).
- **Building code.** `ir::Builder` is a cursor with helpers (`bin`, `load`, `store`, `call`, `condbr`, …) that record the origin bytecode index.
- **Stale references.** Read operands again after earlier edits. A recorded `Value` may name an instruction you already removed; `zext_elim` had exactly this bug.

The pipeline validates the IR after every pass in debug builds (gopt `verify_each`), and always at the end. A pass that breaks SSA, dominance or operand kinds fails with `InvalidIr`. Never rely on validation being skipped.

## Semantics to respect

- Constants are exact `u64`. Fold with `ir::eval`, which implements RFC 9669: shift masking, division by zero, 32-bit zero-extension. Don't fold by hand.
- A `.32` result has zero upper bits. `zext.32.64` of it is redundant, but `sext` is not.
- Calls clobber r1..r5. Loads and stores through pointers may alias anything except ePass slots (`slot*` ops).
- `opaque` instructions are emitted verbatim on fixed registers. Don't look inside them.
- Never introduce reads of values that are undefined on some path, including arguments to calls of unknown arity. The verifier rejects reads of uninitialized registers, and the semantic tests check for them (`epass_interp::uninit_reads`).

## Tests

- **Unit behavior.** Add a `.epir`-based test to `core-rs/epass-std/tests/passes.rs` using the `run_pass(src, "mul_to_shl", opts())` helper, which parses, runs the pass, validates and prints.
- **Semantics.** Passes that are on by default are automatically covered by `semantic.rs`: the defect regression set, 10,000 random programs at three register budgets, and Falco, all checked against the reference interpreter. Add a generator shape to `Gen` in `semantic.rs` if the pattern your pass targets is rare.
