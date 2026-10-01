# ePass core (v2)

`core-rs` is the ePass v2 compiler: an SSA compiler for eBPF programs whose core runs unchanged in userspace and inside the Linux kernel. The design is in [`../design.md`](../design.md) and the milestones in [`../docs/v2/MILESTONES.md`](../docs/v2/MILESTONES.md).

## Workspace

```text
core-rs/
├── epass-core/    #![no_std], zero dependencies: the compiler (also built into the kernel)
│   └── include/epass.h   the C ABI
├── epass-std/     userspace host (system allocator, fault injection), disassembler,
│                  and the integration test suites
├── epass-interp/  reference eBPF interpreter: the semantic oracle for tests
├── epass-capi/    libepass.a / libepass.so for userspace loaders (ePass-libbpf)
├── epasstool/     CLI: ELF, dump, .epir and blob inputs
└── scripts/check.sh   every gate (tests, clippy, no_std, MSRV 1.85, C ABI, optional Miri)
```

## Pipeline

```text
bytecode ──lift──▶ SSA IR ◀──decode── IR blob (untrusted; validated)
                     │
                pass manager (policy + popt → one fixed order; validated after each pass)
                     │
              codegen: critical-edge split → MIR → liveness → interference
                       → MCS coloring with hints, spill-everywhere, memory phis, slot sharing
                       → coalescing → parallel-copy SSA-out → frame below the program's
                       → chain layout → encode with gotol relaxation + offset map
                     │
                     ▼
                  bytecode ──▶ verifier
```

`epass_core::driver::run` does all of this in one call, and applies the administrator policy (fail open or closed). The C ABI, epasstool and the kernel glue all go through it.

## epass-core modules

| Module | Contents |
|---|---|
| `mem` | `Host` trait, per-compilation `Heap` with a byte limit, fallible containers (`FVec`, `ChunkVec`, `IdxVec`/`Arena`, `BitSet`). Holds most of the `unsafe` |
| `ctx`, `log`, `error` | `Ctx` (heap, ring-buffer log, `Limits`, cooperative `Budget`), small `Copy` errors mapped to errnos |
| `bpf`, `facts` | ISA constants; the facts view (helper/kfunc signatures, ISA level) |
| `ir` | functions, blocks, intrusive instruction and use lists, builder, validator, constant evaluation, `.epir` printer and parser (`text` feature) |
| `bin` | binary IR blob |
| `lift` | iterative Cytron SSA construction from bytecode |
| `analysis` | CFG/RPO, dominators, stack provenance and frame extent, magnitude (with counted-loop bounds), value classes, upper-zero |
| `pm`, `passes` | declarative pass registry, policy and popt, the built-in passes |
| `cg` | MIR, register allocation, SSA-out, frame layout, block layout, encoding |
| `driver` | gopt, ISA target, policy dispositions, offset map |
| `ffi` | the C ABI (`ffi` feature). The other module with `unsafe` |

Rules enforced by `check.sh`:

- no panics: clippy denies unwrap, expect, indexing, panic and unreachable;
- every allocation is fallible;
- no recursion;
- MSRV 1.85 (Linux 7.2's minimum);
- builds for `x86_64-unknown-none`.

## Quick start

```bash
cargo build --release
./target/release/epasstool read -F asm bpftests/falco/prog10.txt
./scripts/check.sh
```

See [`../docs/v2/USAGE.md`](../docs/v2/USAGE.md) for the CLI, gopt/popt/policy and libbpf. [`../docs/v2/ABI.md`](../docs/v2/ABI.md) covers the C ABI, [`../docs/v2/IR.md`](../docs/v2/IR.md) the IR, and [`../docs/v2/WRITING_PASSES.md`](../docs/v2/WRITING_PASSES.md) writing passes.

## Results (2026-09-30)

- Falco corpus: 337 of 339 compile. The other two use callbacks (`BPF_PSEUDO_FUNC`, phase 2). The total goes from 148,438 to 126,560 instructions (−14.7%) in about 330 ms.
- Differential testing against the interpreter: 10,000 random programs × 3 register budgets, the defect regression set, and 30k-instruction generated programs, with no mismatches.
- 200,000 straight-line instructions compile in about 0.36 s, with a 72 MB peak heap. The largest Falco program peaks at 3.7 MB.
- The whole pipeline runs on a 16 KB stack. Allocation failure at every allocation, and interruption at every yield point, end cleanly with no leaks.
