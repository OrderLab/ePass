# ePass

[![Build ePass](https://github.com/OrderLab/ePass/actions/workflows/build.yml/badge.svg)](https://github.com/OrderLab/ePass/actions/workflows/build.yml)

ePass is an SSA-based compiler framework for eBPF programs. It lifts eBPF
bytecode into an LLVM-like IR, runs configurable IR passes, and lowers IR back to
eBPF bytecode for kernel verifier/JIT consumption.

The actively developed core is the Rust userspace library under `core-rs/`. The
old C implementation under `deprecated/core/` remains as historical reference.

## Current architecture

```text
eBPF bytecode
  -> lift
  -> ePass SSA IR
  -> pass manager
  -> register allocation + codegen
  -> eBPF bytecode
  -> kernel verifier
```

Key components:

- `core-rs/epass-ir`: pure userspace Rust library. No kernel headers and no
  libbpf dependency.
- `core-rs/epasstool`: CLI for dump-format and ELF-object workflows. ELF support
  uses libbpf only in the CLI.
- `third-party/ePass-libbpf`: patched libbpf that can call the Rust C ABI
  (`epass_run`) before loading programs.
- `third-party/ePass-bpftool`: bpftool built against the patched libbpf for
  verifier testing.

## Features

- SSA IR with arena allocation and typed handles (`InsnId`, `BbId`).
- eBPF bytecode lifter with CFG discovery and SSA construction.
- Pass manager with default-enabled and optional passes, pass-specific options,
  pass-owned ordering, and post-pass validation.
- Built-in passes: `const_prop`, `phi`, `optimize_ir`, optional `dump_ir`.
- Register allocation and codegen back to eBPF bytecode.
- Parseable `.epir` IR text dump/load format for debugging.
- `IrBuilder` and CFG editing utilities for pass authors.
- C ABI for patched libbpf integration.

## Build

Rust core and CLI:

```bash
cd core-rs
cargo build --release
cargo test --release
```

Patched libbpf and bpftool for verifier testing:

```bash
cd third-party/ePass-libbpf/src
make -j

cd ../../ePass-bpftool/src
make -j
```

## CLI quick start

```bash
cd core-rs

# Rewrite an ELF object's selected BPF program and emit dump-format output.
./target/release/epasstool read -s prog -F log -o out.txt ../test/output/progs_simple1.o

# Process dump-format input: one packed u64 per line.
./target/release/epasstool read -F log -o out.txt prog.txt

# Print without rewriting.
./target/release/epasstool print --gopt print_dump ../test/output/progs_simple1.o

# Dump lifted IR before normal passes.
./target/release/epasstool read -P --popt 'dump_ir(/tmp/prog.epir)' -s prog ../test/output/progs_simple1.o

# Load IR directly instead of lifting bytecode, then run passes and codegen.
./target/release/epasstool read --gopt load_ir=/tmp/prog.epir -F log -o out.txt dummy.txt
```

## libbpf / verifier testing

The patched libbpf runs ePass when enabled by environment variable:

```bash
sudo LIBBPF_ENABLE_EPASS=1 \
     LIBBPF_EPASS_GOPT='verbose=1' \
     third-party/ePass-bpftool/src/bpftool prog load test.o /sys/fs/bpf/test
```

The rewritten bytecode is submitted to the kernel verifier. Use `bpftool prog
show pinned ...` to compare `xlated` byte sizes and confirm the modified program
was loaded.

## Documentation

- [Rust core architecture](docs/CORE_RS.md)
- [Pass manager and pass options](docs/PASS_MANAGER.md)
- [Writing passes](docs/WRITING_PASSES.md)
- [IR text format](docs/IR_TEXT.md)
- [IR builder and instruction construction](docs/CREATE_INSTRUCTION.md)
- [Userspace / libbpf testing](docs/USERSPACE_TESTING.md)
- [Testing](docs/TESTING.md)

## Status

- Core lifter, IR, pass framework, codegen, IR text load/dump, and verifier
  testing path are active in `core-rs`.
- Several old C demo/instrumentation passes (MSan, insn counter, masking,
  helper validation, etc.) are not yet fully ported.
- bpf-to-bpf calls and atomic memory ops remain unsupported/limited.

## Contact

Feel free to open an issue or email <xiangyiming2002@gmail.com>.
