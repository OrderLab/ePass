# ePass Rust Core

`core-rs` is the actively-developed userspace ePass compiler core. It is a
from-scratch Rust re-architecture of the original C `core/` implementation.

The core library (`epass-ir`) has no kernel or libbpf dependency. It exposes an
SSA IR, a pass manager, a register-allocating code generator, an IR text
serializer/parser, and a small C ABI used by patched libbpf.

## Workspace layout

```text
core-rs/
├── epass-ir/      # pure Rust compiler library
└── epasstool/     # CLI; uses epass-ir and libbpf-sys for ELF I/O
```

## Pipeline

```text
eBPF bytecode
  -> lift
  -> SSA IR
  -> pass manager
  -> codegen prep
  -> liveness + register allocation
  -> normalization/emission
  -> eBPF bytecode
```

The default pass pipeline is pass-owned and ordered by pass registration:

```text
const_prop -> phi -> optimize_ir
```

Optional passes, such as `dump_ir`, are enabled with `--popt` and order
themselves. For example:

```bash
epasstool read -P --popt 'dump_ir(/tmp/prog.epir)' prog.o
```

runs:

```text
dump_ir -> const_prop -> phi -> optimize_ir
```

## Main modules

| Module | Responsibility |
|--------|----------------|
| `bytecode` | `BpfInsn` and BPF opcode constants; packed `u64` encode/decode |
| `ir` | Arena IR (`Function`, `BasicBlock`, `Insn`, `Value`), `IrBuilder`, CFG utilities, printer, `.epir` text I/O |
| `lift` | eBPF bytecode -> SSA IR with CFG discovery and SSA construction |
| `cfg` | Reachable block layout and end-block computation |
| `check` | IR verifier; includes def-use, branch, and phi predecessor checks |
| `pass` | Pass trait, pass option parsing, pass-owned ordering, postprocess |
| `passes` | Builtins: `dump_ir`, `const_prop`, `phi`, `optimize_ir` |
| `cg` | Code generation: liveness, interference, RA, spilling, SSA-out, emission |
| `pipeline` | End-to-end driver (`autorun`, `run_passes_only`) |
| `ffi` | C ABI (`epass_run`) for patched libbpf |

## Build and test

```bash
cargo build --release
cargo test --release
```

## CLI examples

```bash
# Rewrite an ELF BPF program and dump rewritten bytecode.
./target/release/epasstool read -s prog -F log -o out.txt ../test/output/progs_simple1.o

# Process dump-format text input.
./target/release/epasstool read -F log -o out.txt prog.txt

# Print a program.
./target/release/epasstool print --gopt print_dump ../test/output/progs_simple1.o

# Dump lifted IR before other passes.
./target/release/epasstool read -P --popt 'dump_ir(/tmp/prog.epir)' -s prog ../test/output/progs_simple1.o

# Load IR directly, bypassing lift, then run passes/codegen.
./target/release/epasstool read --gopt load_ir=/tmp/prog.epir -F log -o out.txt dummy.txt

# Disable a disableable default pass.
./target/release/epasstool read --popt '!const_prop' -s prog ../test/output/progs_simple1.o
```

## Global options (`--gopt`)

Comma-separated:

- `verbose=<n>`
- `disable_coalesce`
- `print_bpf`
- `print_dump`
- `print_detail`
- `print_bpf_detail`
- `no_prog_check`
- `printonly`
- `dotgraph`
- `load_ir=<path>`

## Pass options (`--popt`)

Pass options do not determine order. They enable/disable/configure passes; each
pass owns its ordering.

Syntax:

```text
pass
pass(arg)
!pass
```

Examples:

```text
dump_ir(/tmp/a.epir)
dump_ir(path=/tmp/a.epir)
!const_prop
optimize_ir(no_dead_elim)
```

`phi` is not disableable.

## Library usage

```rust
use epass_ir::{autorun, default_passes, Env, Opts, BpfInsn};

let mut env = Env::new(Opts::default(), program /* Vec<BpfInsn> */);
let passes = default_passes();
autorun(&mut env, &passes)?;
let rewritten = env.insns;
```

Dump/load IR:

```rust
let text = epass_ir::dump_ir(&func);
let func = epass_ir::load_ir_str(&text)?;
```

Build IR in passes:

```rust
use epass_ir::ir::{IrBuilder, InsertPos, Value, AluOp, BinOp};

let mut b = IrBuilder::before_terminator(func, bb);
let x = b.bin(BinOp::Add, AluOp::Alu64, Value::const64(1), Value::const64(2));
```

## Validation

Useful checks:

```bash
cargo test --release

# Generate EPIR test corpus
./target/release/epasstool read -P --popt 'dump_ir(/tmp/prog.epir)' -s prog ../test/output/progs_simple1.o

# Verifier path through patched libbpf/bpftool
sudo LIBBPF_ENABLE_EPASS=1 third-party/ePass-bpftool/src/bpftool prog load test.o /sys/fs/bpf/test
```

## More documentation

- [Rust core architecture](../docs/CORE_RS.md)
- [Pass manager](../docs/PASS_MANAGER.md)
- [Writing passes](../docs/WRITING_PASSES.md)
- [Instruction construction / `IrBuilder`](../docs/CREATE_INSTRUCTION.md)
- [IR text format](../docs/IR_TEXT.md)
- [Testing](../docs/TESTING.md)

## Status

Implemented:

- lifter and SSA IR;
- pass manager with pass-owned ordering;
- `const_prop`, `phi`, `optimize_ir`, optional `dump_ir`;
- `.epir` dump/load;
- `IrBuilder` and CFG/BB utilities;
- register allocation with post-spill fallback;
- C ABI for libbpf.

Not yet fully ported from old C core:

- MSan;
- instruction counter;
- masking;
- helper validation;
- div-by-zero instrumentation;
- code compaction demo pass;
- verifier-dependent kernel passes.
