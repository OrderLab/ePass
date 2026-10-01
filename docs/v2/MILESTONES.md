# ePass v2 milestones

This is the implementation plan for the agreed design in [`design.md`](../design.md). Each milestone is one commit (or a short series of commits) on the `refactor/kernel` branch, pushed when its exit criteria pass. The tree builds and `cargo test --release --workspace` passes at the end of every milestone.

## Decisions taken at plan time (2026-09-30)

- **Kernel base: Linux 7.2.y** (7.2.8, the latest stable on 2026-09-30). The old integration (`OrderLab/ePass-kernel`, branch `dev`) is on 6.6.34; v2 doesn't port it forward. The new integration is written against 7.2 because it has the most mature kernel Rust support (the kernel's own allocation API, built-in Rust objects called from C) and the current BPF ISA (v4, `gotol`, MEMSX).
- **Where the kernel code lives.** The kernel-side ePass code is kept in this repository under `kernel/`, as three things:
  - overlay files (the Rust built-in object under `kernel/bpf/epass/` and the C glue);
  - a patch series for the few upstream files that change (uapi `bpf.h`, `kernel/bpf/syscall.c`, Kconfig and Makefiles);
  - a script that applies both onto a vanilla `v7.2.8` tree and syncs `core-rs/epass-core/src` into it.

  This keeps every milestone reviewable, and pushable to one branch, without pushing a kernel history. A kernel tree with the overlay applied can later be pushed to `OrderLab/ePass-kernel` if wanted.

  **Changed 2026-10-01 (user request).** The kernel is now a real kernel tree: branch `refactor/kernel` of OrderLab/ePass-kernel, used as the submodule `third-party/ePass-kernel`. Its commits are the vanilla 7.2.8 snapshot (as root, like the `dev` branch's `init`), the uapi change, the ePass hook and glue, and generated core syncs. `kernel/` in this repository keeps only `sync-core.sh` and the tests; the overlay, the patches and `apply.sh` are gone.
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

## Implementation notes (deviations and additions to design.md)

Recorded as each milestone lands. The M6 docs fold these in.

### M5

- **Memory phis.** A spilled phi is not reloaded into a temporary at each predecessor. It becomes a *memory phi*: its inputs are written straight into its spill slot on each incoming edge (`PVal::Slot`). This avoids the "too many simultaneous phi temporaries" failure at `ra_colors=4`.
- **Location-based sequentializer.** The edge parallel copy works over registers and slots alike (`cg/ssaout.rs`). Cycles break through a free register or the `Scratch` slot. A slot-to-slot move with no free register goes through r0, which is saved in a second scratch slot (`Scratch2`). The sequentializer is checked exhaustively: every permutation of up to 5 locations, each one a register or a slot, with and without free registers.
- **Slot sharing.** Spill slots whose live ranges don't interfere share frame space (first-round interference graph). Without this, large Falco programs ran out of the 512-byte frame.
- **Register hints.** The lifter records the original register of each value (`InsnData.hint`, not part of the IR formats), and coloring tries it first. Falco: 148,438 → 130,450 instructions.
- **Frame extent.**
  - A pointer passed to a helper counts at its lowest possible offset, because helpers access `[ptr, ptr+size)` upward.
  - Pointer spills are tracked only when they are exact 8-byte stores. The verifier rejects narrower pointer spills ("invalid size of register spill"), and codegen keeps every store, so such a program is rejected either way.
- **Counted-loop bound** (`analysis/facts.rs`, `iv_range`).
  - Shape: `p = phi(c0, p + s)`, where the back edge is reached only through the not-equal edge of `p == e` or `p + s == e`, and `e - c0` is an exact multiple of `s` in the walking direction.
  - Result: `p` is bounded by `[c0, e]` (or one step short of `e`) without wrapping.
  - This bounds `r10 + c + iv` frame walks. Falco prog195 and prog198 now compile.
- **Falco result:** 337/339. The two rejected programs load a callback address (`ld_imm64` `BPF_PSEUDO_FUNC`), which is phase 2 per design.md §11.

### M6

- **C ABI shape** (`epass-core/include/epass.h`, `docs/v2/ABI.md`).
  - `epass_compile` returns 0 (use the output), 1 (load the original: skipped or failed open, with `out->error`) or a negative errno (reject). The policy semantics therefore live in the core, and the glue only follows the return value.
  - Facts are C callbacks; NULL means the built-in helper table.
  - Limits travel in `epass_policy`, with a user or kernel preset.
  - Output buffers come from the host allocator.
  - The kernel uses the same entry point. Its glue supplies a C host (kvmalloc, cond_resched) and facts (verifier protos), so the Rust object needs no kernel-crate bindings.
- **Contiguous allocations.** `FVec` allocates contiguously up to 16 MB, not one 64 KB chunk as design.md §3 says. The kernel host must therefore use `kvmalloc`/`kvfree`. Alignment is at most 8.
- **Entry registers.** At entry only r1 is a parameter; r0 and r2–r9 are `undef`. Before this fix, a helper of unknown arity (e.g. `trace_printk` with optional arguments) made ePass preserve r4/r5 from entry, a read the verifier rejects. The semantic gate now checks that output never reads a register the input left uninitialized (`epass_interp::uninit_reads`).
- **Bugs found while porting.**
  - `zext_elim` left a use of a removed `zext` in a chain of zexts (bpftests `complex.c`). The generator now emits such chains.
  - Chain block layout parked one arm of every diamond at the end of the program, which needed `gotol` beyond 32K instructions. A join is now entered by fallthrough only after all its forward predecessors are placed.
  - Unhinted temporaries got r0, causing extra copies. Hints are now propagated across two-address ties and copies. Falco: 130,450 → 126,560 instructions.
- **gopt keys:** `verbose`, `isa`, `ra_colors`, `throw_ret`, `check`/`nocheck`, `verify_each`, `endian`.
  - Default ISA target: the input's own level for bytecode, the platform's for IR, capped at the platform's.
  - Removed v1 keys: `print_*` (use `-F`), `load_ir` (pass `.epir` or a blob as the input), `disable_coalesce`, `dotgraph`.
  - `dump_ir` writes to the log, not to a file.
- **ePass-libbpf** (`refactor/kernel`, 5e84bc3).
  - It now uses `epass_compile`, reads popt from `LIBBPF_EPASS_POPT`, and fails open instead of failing the load.
  - `func_info`/`line_info` are remapped through the offset map (stable sort, one record per offset), instead of `line_info` being dropped.
- **Measurements** (release, this host):
  - 200,000 straight-line instructions: 0.36 s, 72 MB peak heap (368 B/instruction). The kernel preset caps input at 65,536 instructions and 64 MB.
  - Largest Falco peak: 3.7 MB (prog196, 8,398 instructions).
  - All of `bpftests/*.c` that clang can build compile (28 of 30), except `asm.c` (ecall in bytecode) and `localcall.c` (bpf-to-bpf).

### M7

- **Where the code lives.** At M7, kernel code was in `kernel/` (overlay, patches, `apply.sh`, the selftest) and applied to vanilla v7.2.8. Since 2026-10-01 it lives in the ePass-kernel submodule; see the plan-time decisions above.
- **No kernel-crate bindings.** The Rust object only uses `core`. It exports the C ABI, and `kernel/bpf/epass.c` supplies the host and the facts as C callbacks. This follows the `drm_panic_qr.rs` precedent: a built-in Rust object called from C.
  - `epass_policy_check` was added to the ABI, so the policy sysctl validates on write and the hot path decides without compiling.
- **Kernel constraints found while porting.**
  - The kernel's `compiler_builtins` panics on 128-bit division, and `iv_range` used i128. It now uses checked i64 arithmetic, and `check.sh` scans the no_std object for 128-bit and float intrinsics.
  - The crate is built with `-Coverflow-checks=off`, because `CONFIG_RUST_OVERFLOW_CHECKS` would turn any wrap into a `BUG()`. Signed division folding is written with `checked_div`/`checked_rem`, so no div-by-zero panic path remains. The only panic symbol left in the object is core's sort-order check, which is unreachable for integer keys.
  - `prog->aux->ops` is `bpf_prog_ops`, and the verifier ops are static in verifier.c. Patch 0002 adds `bpf_epass_func_proto()`.
- **Decisions on design.md open questions.**
  - Pass options and IR need CAP_BPF; global options don't.
  - The policy lives in a sysctl, `kernel.bpf_epass_policy`. CAP_SYS_ADMIN writes it; the default is `mode=optin`.
  - `BPF_F_EPASS` is `1U << 30`, chosen to stay clear of upstream's next flags.
  - CO-RE relocations and bpf-to-bpf programs keep the original instructions, and are rejected only when a pass is forced.
  - ePass runs before `security_bpf_prog_load()`, so LSMs see the program that is verified.
  - Signatures (`attr->signature`) are checked over the submitted program before ePass runs.
- **line_info.** It is remapped in the kernel. The glue builds a sorted, deduplicated copy, and `check_btf_line()` reads from it through a one-line hook. func_info needs no remap: with a single function its only record is at offset 0, and `offsets[0]` is always 0.
- **Test VM.** An incus VM (`ubuntu/noble`) runs the kernel, configured from the VM's own config plus `localmodconfig`. The host needed `ovmf`, `qemu-system-modules-spice`, `debhelper` and `libdw-dev`, and `incusbr0` had to be added to firewalld's trusted zone (Docker's FORWARD DROP also needs `DOCKER-USER` accept rules for the bridge).

### M8

- **ePass-libbpf** (`refactor/kernel`, d0d1ed5).
  - The uapi is synced with 7.2 plus the ePass fields. libbpf 1.6's attr ended at `fd_array_cnt`, and 7.2 inserts the signature fields before ours.
  - `bpf_prog_load_opts` has `epass_gopt`, `epass_popt`, `epass_ir` and `epass_ir_len`.
  - `LIBBPF_EPASS_KERNEL=1` switches the hook from userspace ePass to `BPF_F_EPASS` plus kernel options.
- **bpftool.** No source changes: ePass-bpftool builds on ePass-libbpf, so the environment variables apply. `kernel/tests/build.sh` builds it statically (it needs `feature-libelf-zstd=1` for the static libelf), together with the selftest and `epass_logs`.
- **Acceptance** (docs/v2/ACCEPTANCE.md, raw data in acceptance-results.csv).
  - 111 test objects: `test/` built against the VM kernel's `vmlinux.h`, plus the kernel samples. 81 load at base, and the same 81 load with ePass in userspace, in the kernel, and under `mode=always`.
  - All 69 available CORRECT_PROGS are accepted in all modes.
  - In-kernel ePass compiles all 121 programs of the accepted objects. The xlated total is 54,136 → 53,440 bytes.
  - The policy and IR cases pass in the selftest (56/56), and dmesg is clean.
- **Code size.** ePass sometimes grows programs (19 of 81 objects, worst +29%). The cause is a repeated constant phi input that gets materialized on every incoming edge. Hoisting such constants is the next codegen item.
