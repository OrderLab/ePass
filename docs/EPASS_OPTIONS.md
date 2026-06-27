# ePass Options

Options are split into global options (`--gopt`) and pass options (`--popt`).

## Global options (`--gopt`)

`--gopt` is a comma-separated list:

```bash
--gopt 'verbose=2,disable_coalesce'
```

Supported options:

| Option | Meaning |
|--------|---------|
| `verbose=<n>` | Set log verbosity. `0` quiet, `1` info, `2+` debug IR logs. |
| `disable_coalesce` | Disable register coalescing in codegen. |
| `print_bpf` | Print BPF disassembly format. |
| `print_dump` | Print dump format: one packed `u64` per instruction. |
| `print_detail` | Print detailed instruction view. |
| `print_bpf_detail` | Print both BPF and detailed view. |
| `no_prog_check` | Disable IR verifier checks after passes. Mostly for debugging broken IR. |
| `printonly` | Skip transformation. |
| `dotgraph` | Reserved/debug option for graph output. |
| `load_ir=<path>` | Load initial IR from `.epir` instead of lifting bytecode. Passes/codegen still run. |

## Pass options (`--popt`)

`--popt` configures pass enable/disable/options. It does **not** directly define
pass order. Each pass decides its own order via `register_pass`.

Syntax:

```text
pass
pass(arg)
!pass
```

Examples:

```bash
--popt 'dump_ir(/tmp/lift.epir)'
--popt 'dump_ir(path=/tmp/lift.epir),!const_prop'
--popt 'optimize_ir(no_dead_elim)'
```

Commas split options only at the top level, so arguments can contain commas
inside parentheses.

## Builtin passes

### `dump_ir`

Optional. Disabled by default.

```text
dump_ir(/tmp/a.epir)
dump_ir(path=/tmp/a.epir)
```

Orders itself first and dumps the IR immediately after lift/load, before other
passes mutate it.

### `const_prop`

Default enabled. Disableable.

```text
!const_prop
```

Takes no options. Conservatively folds constants and constant conditional
branches.

### `phi`

Default enabled. **Not disableable**.

Removes trivial phi nodes.

### `optimize_ir`

Default enabled. Disableable.

Options:

```text
optimize_ir(no_dead_elim)
optimize_ir(noopt)
optimize_ir(no_dead_elim,noopt)
```

Performs dead-code elimination and unused-alloc removal.

## Default order

Without `--popt`:

```text
const_prop -> phi -> optimize_ir
```

With dump enabled:

```text
dump_ir -> const_prop -> phi -> optimize_ir
```
