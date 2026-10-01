# ePass

[![Build ePass](https://github.com/OrderLab/ePass/actions/workflows/build.yml/badge.svg)](https://github.com/OrderLab/ePass/actions/workflows/build.yml)

ePass is an SSA-based compiler framework for eBPF programs. It lifts eBPF
bytecode into an SSA IR, runs passes under an administrator policy, and lowers
the IR back to bytecode for the kernel verifier and JIT.

**v2** (branch `refactor/kernel`) is a rewrite whose core runs unchanged in
userspace and inside the Linux kernel. It's in [`core-rs/`](core-rs/), the design is in
[`design.md`](design.md), and the plan is in
[`docs/v2/MILESTONES.md`](docs/v2/MILESTONES.md). The old C core under
`deprecated/core/` is historical reference.

## Architecture

```text
bytecode or IR blob ─▶ lift / decode + validate ─▶ SSA IR ─▶ passes (policy + popt)
                    ─▶ codegen (regalloc, SSA-out, frame, layout, relax) ─▶ bytecode ─▶ verifier
```

- `core-rs/epass-core`: `#![no_std]`, no dependencies, no panics, fallible
  allocation everywhere. The same sources build into the kernel. Its C ABI is
  `epass_compile` (`core-rs/epass-core/include/epass.h`).
- `core-rs/epass-capi`: `libepass.a`/`.so` for userspace loaders.
- `core-rs/epasstool`: CLI for ELF objects, dump files, `.epir` text and IR blobs.
- `core-rs/epass-interp`: reference interpreter. All of codegen is tested
  against it.
- `third-party/ePass-libbpf` (branch `refactor/kernel`): libbpf that runs ePass
  before loading, and remaps `func_info`/`line_info`.
- [`third-party/ePass-kernel`](kernel/README.md) (branch `refactor/kernel` of
  OrderLab/ePass-kernel): Linux 7.2.8 with ePass; [`kernel/`](kernel/) has the
  core sync script and the in-VM tests. ePass runs inside `BPF_PROG_LOAD` under the policy in
  `/proc/sys/kernel/bpf_epass_policy`; loaders pass options or IR in new
  `BPF_PROG_LOAD` fields.

## Build and test

```bash
cd core-rs
cargo build --release
./scripts/check.sh        # tests, clippy, no_std, MSRV 1.85, C ABI smoke test

cd ../third-party/ePass-libbpf/src && make -j   # links core-rs libepass.a
```

## Quick start

```bash
T=core-rs/target/release/epasstool
$T read -s prog -o out.txt prog.o               # compile an ELF program to dump format
$T read -F asm prog.txt                         # dump in, assembly out
$T read --gopt verbose=2 --popt dump_ir prog.o  # show the IR in the log
$T lift prog.txt -o prog.epir && $T read prog.epir -F asm

sudo LIBBPF_ENABLE_EPASS=1 LIBBPF_EPASS_GOPT=verbose=2 ./my_loader prog.o
```

## Documentation

- [Usage: CLI, options, policy, libbpf, tests](docs/v2/USAGE.md)
- [C ABI](docs/v2/ABI.md)
- [IR v2](docs/v2/IR.md)
- [Writing passes](docs/v2/WRITING_PASSES.md)
- [Design](design.md) and [milestones](docs/v2/MILESTONES.md)
- [Falcolib build notes](docs/FALCOLIB_BUILD.md)
- v1 docs (archived): [docs/v1/](docs/v1/)

## Status

- Done:
  - the v2 core (lifter, IR, passes, codegen);
  - the C ABI, epasstool, and libbpf userspace mode;
  - the semantic and structural test gates (M0–M6);
  - the kernel integration on Linux 7.2.8 (M7): boots in an incus VM, the
    selftest passes 56/56 with kernel output byte-identical to userspace, and
    337/339 Falco programs compile in-kernel.
- Not supported yet: bpf-to-bpf calls and callbacks. These are rejected, and
  loaders fall back to the original program.
- In-VM acceptance (M8, [report](docs/v2/ACCEPTANCE.md)):
  - libbpf and bpftool support kernel mode;
  - the set of accepted objects is unchanged in userspace, kernel and `mode=always` runs (81 of 111; all 69 CORRECT_PROGS);
  - in-kernel ePass compiles all 121 programs of those objects, and dmesg stays clean.

## Contact

Feel free to open an issue or email <xiangyiming2002@gmail.com>.
