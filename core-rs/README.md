# ePass (Rust)

A userspace Rust port of the ePass eBPF compiler framework: an SSA-based
intermediate representation, a pass pipeline, and a register-allocating code
generator that lowers IR back to eBPF bytecode.

This is a from-scratch, idiomatic re-architecture of the original C `core/`
(see `../core`), targeting **userspace only** (no kernel, no `__KERNEL__`
shims). It produces **bit-identical bytecode** to the C tool on the test corpus.

## Workspace layout

```
core-rs/
├── epass-ir/      # the core library crate (no libbpf dependency)
└── epasstool/     # the CLI (uses epass-ir + libbpf for ELF I/O)
```

### `epass-ir` modules

| Module | Responsibility |
|--------|----------------|
| `bytecode` | `BpfInsn` + BPF ISA opcode constants; packed `u64` encode/decode |
| `ir` | Arena-based IR: `Function`, `BasicBlock`, `Insn`, `Value`, builders, pretty-printer |
| `lift` | eBPF bytecode → SSA IR (CFG discovery + Braun et al. SSA construction) |
| `cfg` | Reachable-block chain layout and end-block computation |
| `check` | IR validity checker (run after every pass) |
| `pass` | `Pass` trait + `PassManager` (pre / custom / post pipeline) |
| `passes` | Built-in passes (currently `remove_trivial_phi`) |
| `cg` | Code generator: SSA-based chordal-graph register allocation + normalization |
| `pipeline` | `autorun` driver (lift → run passes → compile) |
| `helpers` | Static eBPF helper argument-count table |

The IR uses **arena allocation with typed index handles** (`InsnId`, `BbId`)
instead of the raw pointer graph of the C version — no `unsafe`, no `Rc<RefCell>`.
Code-generation state lives in side-tables keyed by `InsnId`, keeping the IR
node type stable across stages.

## Building

Requires a Rust toolchain and a system `libbpf` (for the CLI's ELF support).

```sh
cargo build --release
cargo test
```

## Using the CLI

```sh
# Lift, transform, compile an ELF object; write the rewritten program as a dump
epasstool read --gopt verbose=1 -F log -o out.txt prog.o

# Process a dump-format file (one packed u64 per line)
epasstool read -F log -o out.txt prog.txt

# Print a program without transforming it
epasstool print --gopt print_dump prog.o
```

Global options (`--gopt`, comma-separated): `verbose=<n>`,
`disable_coalesce`, `print_bpf`, `print_dump`, `print_detail`, `no_prog_check`.

## Using the library

```rust
use epass_ir::{autorun, default_passes, Env, Opts, BpfInsn};

let mut env = Env::new(Opts::default(), program /* Vec<BpfInsn> */);
let passes = default_passes();
autorun(&mut env, &passes)?;        // env.insns now holds the rewritten program
println!("{}", env.log_buffer());
```

## Validation

Correctness is checked by diffing the dump-format output against the reference
C `epasstool` on the program corpus under `../test/progs`. The core compiler
path (dump in → dump out) is bit-identical to the C implementation. ELF
section-selection semantics may differ from the C tool; final acceptance is via
the eBPF verifier.

## Status

- Lifter, IR, passes, register allocation, and normalization are complete.
- Built-in analysis/instrumentation passes (msan, insn_counter, div_by_zero,
  code_compaction, etc.) are not yet ported.
- bpf-to-bpf calls and atomic memory ops are unsupported (as in the C version).
