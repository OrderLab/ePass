# Pass Manager

The Rust pass manager uses pass-owned metadata and ordering. Users do not specify
pass order directly. Instead, `--popt` enables, disables, or configures passes;
each pass decides where it belongs.

## Pass trait

```rust
pub trait Pass {
    fn name(&self) -> &str;

    fn enabled_by_default(&self) -> bool { false }
    fn allow_disable(&self) -> bool { true }

    fn init(&mut self, arg: Option<&str>) -> Result<()> { ... }

    fn register_pass(&self, order: Vec<String>) -> Result<Vec<String>> {
        Ok(order)
    }

    fn run(&self, env: &mut Env, func: &mut Function) -> Result<()>;
}
```

`init` is called before any IR mutation. Pass options are parsed once and stored
inside the pass object.

`register_pass` receives the current pass name list and returns a modified list.
The pass manager verifies that a pass only changes entries with its own name.
This permits a pass to move, insert, or remove itself but prevents it from
manipulating other passes.

## Pass option syntax

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

Commas split options at top level, so pass arguments may contain commas inside
parentheses.

## Default passes

Default enabled passes:

```text
const_prop -> phi -> optimize_ir
```

Optional pass:

```text
dump_ir(path)
```

When enabled, `dump_ir` orders itself first:

```text
dump_ir -> const_prop -> phi -> optimize_ir
```

## Builtin passes

### `dump_ir`

- Default: disabled
- Disableable: yes
- Args: required path
- Forms:
  ```text
  dump_ir(/tmp/a.epir)
  dump_ir(path=/tmp/a.epir)
  ```
- Order: first

### `const_prop`

- Default: enabled
- Disableable: yes
- Args: none
- Order: before `phi`

### `phi`

- Default: enabled
- Disableable: no
- Args: none
- Order: before `optimize_ir` if optimizer is present, otherwise last

### `optimize_ir`

- Default: enabled
- Disableable: yes
- Args:
  ```text
  no_dead_elim
  noopt
  ```
- Order: after `phi` / after cleanup passes

## Ordering stabilization

Pass ordering is computed by repeatedly asking enabled passes to register their
preferred position until the list is stable.

Limits:

- maximum iterations: 32
- duplicate pass instances: not supported yet
- if a pass changes any pass except itself, registration fails
- if ordering does not converge, registration fails

This catches ordering cycles such as two passes repeatedly moving themselves
before each other.

## Postprocess

After every pass, the manager runs:

```text
recompute_succs
cfg::finalize
drop_unreachable_edges
prune_phi_inputs
prog_check
```

This means passes may rewrite branches and CFG targets, then rely on postprocess
to clean reachable layout and validate IR.
