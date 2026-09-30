# ePass v2 milestones

This is the implementation plan for the agreed design in [`design.md`](../../design.md). Each milestone is one commit (or a short series of commits) on the `refactor/kernel` branch, pushed when its exit criteria pass. The tree builds and `cargo test --release --workspace` passes at the end of every milestone.

## Decisions taken at plan time (2026-09-30)

- **Kernel base: Linux 7.2.y** (7.2.8, the latest stable on 2026-09-30). The old integration (`OrderLab/ePass-kernel`, branch `dev`) is on 6.6.34; v2 doesn't port it forward. The new integration is written against 7.2 because it has the most mature kernel Rust support (the kernel's own allocation API, built-in Rust objects called from C) and the current BPF ISA (v4, `gotol`, MEMSX).
- **Where the kernel code lives.** The kernel-side ePass code is kept in this repository under `kernel/`, as three things:
  - overlay files (the Rust built-in object under `kernel/bpf/epass/` and the C glue);
  - a patch series for the few upstream files that change (uapi `bpf.h`, `kernel/bpf/syscall.c`, Kconfig and Makefiles);
  - a script that applies both onto a vanilla `v7.2.8` tree and syncs `core-rs/epass-core/src` into it.

  This keeps every milestone reviewable, and pushable to one branch, without pushing a kernel history. A kernel tree with the overlay applied can later be pushed to `OrderLab/ePass-kernel` if wanted.
- **Loader submodules.** Changes to `third-party/ePass-libbpf` and `third-party/ePass-bpftool` go on a `refactor/kernel` branch in each submodule repository. This repository's submodule pointers are bumped in the same milestone.
- **Transition.** The new `core-rs/epass-core` is built next to the existing `core-rs/epass-ir` until M6, when `epasstool` and the C ABI switch over and `epass-ir` is removed. Until then the old crate stays the reference for behavior that hasn't been ported yet.
- **Test VM.** An incus VM (run with sudo) boots the custom kernel. Experiments run over ssh inside it.

## Toolchain

- Userspace: stable Rust (currently 1.98.1), clang 21.
- Miri needs a nightly toolchain with `miri`.
- Kernel: `rust-src` for the kernel's Rust toolchain, `bindgen-cli`, and LLVM with `lld`, because the kernel is built with `LLVM=1`. Also pahole, flex, bison, libelf and libssl (already installed).

## Milestones

| # | Title | Deliverables | Exit criteria |
|---|---|---|---|
| M0 | Plan | `refactor/kernel` branch, `design.md`, this file | pushed |
| M1 | Core foundation and oracle | `core-rs/epass-core` (`#![no_std]`, no dependencies): host trait, fallible chunked containers (`Arena`, `IdxVec`, `FVec`), errors, `Limits`/`Budget`, bounded log. `core-rs/epass-std`: system-allocator host with fault injection. `core-rs/epass-interp`: reference eBPF interpreter | unit tests; `cargo build -p epass-core --target x86_64-unknown-none`; clippy deny lints clean; Miri on containers; interpreter unit tests (ALU32/64 semantics per RFC 9669, memory, jumps, helper stubs) |
| M2 | IR v2 | module, function, blocks, intrusive instruction and use lists; the op set with widths, extensions and exact constants; builder and CFG utilities; validator (per-opcode operand kinds, dominance); `.epir` printer and parser; binary blob encoder and decoder | round-trip tests (text and blob); validator rejects mutated blobs and never panics (mutation test); dominance tests |
| M3 | Lifter v2 and analyses | iterative lifter (synthetic entry, canonical constants, JSET/MEMSX/MOVSX/sdiv/bswap/`gotol`, kfunc via facts, poison, `opaque`, hard errors); dominators, stack provenance, value class, known zero-extension | lifter unit tests per opcode family; all 339 Falco programs and the bpftests lift and validate; 120,001-block program lifts in a 16 KB thread |
| M4 | Pass manager and policy | declarative `PassInfo`, topological order, popt parser, policy string and precedence table, failure semantics; passes `const_prop`, `phi`, `optimize_ir`, `zext_elim`, `dump_ir`, `lower_throw` | policy table tests; order acyclic; pass unit tests on `.epir` inputs |
| M5 | Codegen v2 and the semantic gate | MIR, legalize (immediate rules, ISA gating, swap rule), frame below `orig_depth`, iterative liveness, register allocator port, coalescing, critical-edge split, parallel-copy SSA-out, relax, encode plus offset map, post-allocation checker | 14-program semantic regression set green; differential generator 10,000 programs × `ra_colors` {10, 6, 4} with 0 mismatches; Falco at least 337/339 compile plus the stack invariant |
| M6 | Tooling cutover | `epasstool` on `epass-core` (ELF, dump, `.epir`, blob conversion); C ABI `epass_compile`; ePass-libbpf on the new ABI; old `epass-ir` removed; structural tests (16 KB thread, allocation-fault injection, compile time, memory); docs | the whole workspace is green; 200k-instruction straight-line program in under 5 s |
| M7 | Kernel integration | `kernel/` overlay for Linux 7.2.8: Rust built-in object, C glue in `bpf_prog_load` before `bpf_check`, uapi fields, policy via sysfs, facts view over verifier ops and BTF, `func_info`/`line_info` remap, budget via `cond_resched`; `CONFIG_RUST=y` config | kernel builds; boots in the incus VM; in-kernel smoke test (ePass compiles and loads a program; kernel output byte-identical to userspace) |
| M8 | Loader integration and acceptance | libbpf and bpftool support for the new fields; in-VM end-to-end run over bpftests, Falco and `CORRECT_PROGS`; policy force/deny; IR submission; acceptance procedure and measurement report | set of accepted programs unchanged against the baseline; `EPERM` cases behave as specified; dmesg clean; documents written |
