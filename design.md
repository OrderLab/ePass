# ePass v2 design

Date: 2026-09-30. Measured against `core-rs` at commit `e18bf4a` (main).

Status: **agreed by both authors on 2026-09-30.** Merged from `design0.md` (session epass-94) and `design1.md` (session "Repository overview (2)"). Design only; no code changes. The open questions in §12 are for the user.

Brief: refactor ePass so the compiler core runs both in userspace and inside the kernel. In the kernel it runs at `BPF_PROG_LOAD` under an administrator policy, taking bytecode plus gopt/popt, or ePass IR directly. Fix the confirmed code-generation miscompiles, redesign the IR type system, and replace the design choices that caused the defects.

## 0. Decision

**Take option 1: keep the Rust core and make it kernel-capable.** Keep `core-rs`'s algorithms, IR shape, pass API, text format and tests. Rewrite its plumbing into a dependency-free `#![no_std]` crate that compiles unchanged for userspace and for the kernel's Rust toolchain.

Why not option 2 (rewriting the C core with the Rust architecture):

- **Untrusted input in the kernel.** The kernel will parse IR blobs and option strings from userspace and run a register allocator over them. Memory safety on that path is the primary requirement. Rust provides it structurally, and "no panics, no recursion, every allocation fallible" can be enforced with types and lints. In C it depends on review alone.
- **The fixes already exist in Rust.** So do the arena/handle architecture and the pass framework. The C core's problems are listed in §9. A C rewrite would copy the Rust architecture and then re-fight aliasing and lifetime bugs without compiler help.
- **One source tree.** It builds in both modes, so `cargo test`, Miri, fuzzing and the differential interpreter exercise the code the kernel runs.

**Costs we accept:**

- The ePass kernel must build with `CONFIG_RUST=y`, which only some architectures support.
- The minimum Rust version is tied to the kernel's.
- No crates.io dependencies, and no `std` or `alloc` containers.
- The core must be panic-free and recursion-free. That last requirement would apply in either language: the current recursion overflows even an 8 MB stack (D11).
- Kernel Rust builds with overflow checks on by default, so arithmetic uses explicit `wrapping_*`/`checked_*`.

**What would flip it:** if ePass must run on kernels without Rust, or be upstreamed into `kernel/bpf`, choose option 2. Sections 4–8 are language-neutral and would carry over unchanged.

## 1. Defects the design must remove

All of these were found on 2026-09-30. "Measured" means dump-format programs were run through a reference eBPF interpreter before and after `core-rs/target/release/epasstool read`, or through epasstool alone where noted. Paths are relative to `core-rs/epass-ir/src/`.

| Id | Input | Output today | Root cause | Evidence |
|---|---|---|---|---|
| D1 | `w0 = w2`, r2 = 0x1_00000005 | `0x100000005` (should be `0x5`) | `mov32 X` lifts to an SSA rebind, so the truncation is lost (`lift.rs:497`) | measured |
| D2 | `w2 = -1; r0 += r2` | adds `-1` (should add `0xffffffff`) | constants carry an `AluOp` tag; `emit_load_const` emits every 32-bit constant as `mov64 K` (`cg/norm.rs:245`) | measured |
| D3 | `if r2 & 1 goto` (JSET) | branch deleted | `is_cond_jump_op` includes JSET (`lift.rs:76`) but `translate_jmp` has no JSET case; `fill_block` turns the error into a no-op (`lift.rs:399`) | measured |
| D4 | `r0 = *(s8 *)(r1+0)` | `0xff` (should be `-1`) | MEMSX is routed to `translate_load` and emitted as MEM | measured |
| D5 | `r0 = (s8) r2` (MOVSX) | no `exit` in the output | `off != 0` is rejected (`lift.rs:482`), then r0 is undefined, so `exit` is dropped as well | measured |
| D6 | `r2 = 1; r2 <<= 40; r0 += r2`, and also `0x7fffffff + 0x7fffffff` then `r2 += r1` | `r0 += 0` and `r2 += -2` | `const_prop` folds to a value that doesn't fit imm32; emission encodes `v as i32` with no check | measured (both) |
| D7 | loop that swaps two values through phis | `0x11` (should be `0x21`) | `remove_phi` emits sequential copies (`cg/alloc.rs:349`) | measured |
| D8 | branch block whose two successors both have phis | `0x410` (should be `0x406`) | lost copy: both copies land in r0 at the end of the shared predecessor, and there's no critical-edge splitting | measured |
| D9 | `r2 = r10; r2 += -16` alongside direct `*(r10-16)` accesses, under spills | pointer lands in ePass's spill slots | `ConstKind::RawOff` / `add_stack_offset` (`cg/prepare.rs`) shift only direct `[r10+K]` accesses | static scan: 16 of the 18 spilling Falco programs affected (e.g. prog273: S=32, pointers `r10-8/-16/-20/-32` in the spill area) |
| D10 | pc 0 is a loop header | output loops forever | `read_var` returns the argument registers in the entry block (`lift.rs:207`), so back edges into pc 0 get no phis | measured |
| D11 | 120,000-block program (a chain of `ja +0`) | abort (stack overflow) on the default 8 MB stack | recursive `fill_block` and `read_var_recursive` (`lift.rs`); `live_in_at_statement`, `live_out_at_statement` and `phi_conflict_at_block` (`cg/liveness.rs`) | measured. Under `ulimit -s 16`, Falco prog195 (3,012 insns) crashes 20 of 20 runs and prog1 (196 insns) 15 of 20, but a 2-instruction program also crashes 3 of 20, so the gate is a 16 KB thread (§10) |
| D12 | bpf-to-bpf call, kfunc call (`src=2`), atomics, sdiv/smod (`off=1`), LD_ABS/IND | each instruction silently becomes a no-op | same catch-all as D3; `src=2` is mislabeled "platform-specific" (`lift.rs:667`) | code reading (same code path as D3) |
| D13 | `r1 = 7; call 250; exit` (helper id with no table entry) | exactly one instruction: `call 250`, with no argument setup and no exit | `create_insn` runs before the arity check (`lift.rs:674`) | measured (both) |
| D14 | `throw` from any pass | bare `exit` with garbage in r0 | `cg/norm.rs:381`; `translate_throw` from `deprecated/core/passes/translate_throw.c` was never ported | code reading |

**Related observations:**

- **`.epir` round trip.** The dumper writes a `+sp` suffix that `parse_addr` rejects (`ir/text.rs:412`), so 30 of the 78 files in `core-rs/epass-ir/tests/epir/` don't load.
- **Superlinear compile time.** `prev_insn`/`next_insn` do a linear `position()` search (`ir/mod.rs:598`). A straight-line program takes 1.2 s at 10k instructions, 40 s at 50k, and over 120 s at 200k.
- **No semantic oracle.** The tests only check that the tool exits cleanly. `cargo test --release` passes with D1–D14 all present.
- **Falco counts.** `test/progs/falco` has 340 `.txt` files: 339 programs plus `progs.txt`, an index file. `core-rs/epasstool/tests/falco.rs` feeds `progs.txt` to epasstool as a program, which parses to an empty program and counts as a pass. So today 337 of the 339 real programs pass, with prog195 and prog198 as the known failures.
- **What Falco lacks, and why that matters.** The corpus is 64-bit ALU only, with no JSET, ALU32, MEMSX, local calls or kfunc calls. But clang 21's default output does use ALU32: 9 of the 30 objects built from `core-rs/bpftests/*.c` contain `wN = wM` moves.

## 2. Scope split

Built in this order:

1. **Compiler core** (this repository): §3–§8. That includes the C ABI and the binary IR format that piece 2 consumes. Designed fully here.
2. **Kernel and loader integration** (ePass-kernel, ePass-libbpf, ePass-bpftool): uapi fields, syscall glue, policy store, Kbuild wiring, and the libbpf/bpftool options. It's designed at interface level in §7, and can only be specified against piece 1's ABI. Userspace loader work can start once the blob format is frozen.

## 3. Core architecture (piece 1)

### Crates

- **`core-rs/epass-core`**: `#![no_std]`, zero dependencies. Modules:
  - `mem`: host trait and containers; the only `unsafe`.
  - `bpf`: ISA constants and `BpfInsn`.
  - `ir`: module, function, instructions, values, builder, validator.
  - `analysis`: dominators, liveness, stack provenance, value class, known zero-extension.
  - `lift`.
  - `passes`.
  - `pm`: pass manager and policy.
  - `cg`: legalize, frame, allocate, SSA-out, MIR, relax, encode.
  - `bin`: binary IR.
  - `ffi`: C ABI.
  - `text`: `.epir`, feature-gated, userspace only.
- **`core-rs/epass-std`**: a userspace host over the system allocator, with a fault-injection mode. Also holds ELF I/O via `libbpf-sys`, `epasstool`, `epass-interp` (the semantic oracle, §10), and fuzz targets.
- **Kernel side:** `kernel/bpf/epass/` is a built-in Rust object with one crate root and a mod tree, not part of the `kernel` crate. It contains:
  - a synced copy of `epass-core/src`, produced by a script in the style of `deprecated/core/scripts/gen_kernel.sh`;
  - a host implementation over kmalloc and printk;
  - C glue in `kernel/bpf/epass.c`.

### Host boundary

One trait:

- `alloc(layout) -> Option<NonNull<u8>>`
- `free(ptr, layout)`
- `log(level, &str)`
- `now_ns()`
- `should_yield() -> Result<(), Interrupted>`: the kernel host calls `cond_resched()` here and checks `fatal_signal_pending()`.

Nothing else in the core touches the platform. Program facts (helper and kfunc signatures, map metadata, program type, ISA level) come through a separate facts view (§7).

### Containers (about 700 lines, Miri-tested)

- **`Arena<T>`**: 64 KB chunks, typed `u32` ids, tombstones.
- **`IdxVec<Id, T>`**: dense side tables, also 64 KB chunks with shift/mask indexing. No container ever makes a contiguous allocation larger than one chunk, so plain kmalloc suffices and the host needs no kvmalloc. It replaces `HashMap<InsnId, CgExtra>` (`cg/mod.rs:69`); HashMap isn't available in kernel Rust.
- **Intrusive instruction list**: prev/next ids are stored in the arena, so `prev_insn`/`next_insn` are O(1).
- **Intrusive use lists**: each operand slot is a `Use` node linked into its def's list, LLVM-style. Maintaining def-use allocates nothing, and `users: Vec<InsnId>` goes away.
- **`SparseSet`** for liveness, **`BitSet`** for dominators.

Every allocation is fallible and surfaces as `Error::OutOfMemory`.

### Resource bounds

- **`Limits { max_insns, max_bytes }`**: the host counts bytes, and exceeding a limit returns `Error::Limit`.
- **`Budget`**: ticked in every loop of the core. Every N ticks it calls the host's `should_yield()`. The kernel host resched's and returns `-EINTR` on a fatal signal. There's also a time limit from policy; the userspace host uses a wall-clock limit so tests exercise the same path.

### No recursion

- The lifter fills blocks from an explicit worklist in reverse postorder.
- Braun's variable lookup runs with an explicit stack.
- Liveness is block-level dataflow over sparse sets.
- Dominators use the iterative Cooper–Harvey–Kennedy algorithm.

### No panics

- No `unwrap`, `expect`, `assert!`, `unreachable!` or unchecked indexing anywhere in `epass-core` outside `mem`, enforced by clippy `deny` lints.
- Arena access is checked, and returns `Error::Internal` in release builds.
- Invariants are `debug_assert`s.

### Logging

- A fixed-size ring buffer through the host. In the kernel it's copied into the loader's verifier `log_buf` with a prefix.
- Whole-IR dumps are userspace only.

### Kernel build and CI

- CI approximates the kernel's constraints with `cargo build -p epass-core --no-default-features --target x86_64-unknown-none`. The real gate is the Kbuild in piece 2.
- A freestanding `staticlib` linked into vmlinux stays as the fallback if `CONFIG_RUST` proves unusable on the target kernel. It needs a custom target JSON with nightly `build-std`.

## 4. IR and type system

### Value model

Every SSA value is a 64-bit register bit pattern; there are no i32 values. Width lives on operations, as in the ISA, and a 32-bit operation's result is defined as zero-extended.

`Value = Insn | Const(64-bit pattern) | Param(1..5) | FramePtr | Undef | Builtin(kind)`.

- `Undef` is legal as a phi operand and as a copy source, and emits nothing.
- `Builtin` is reserved (see "Reserved variants" below).

### Is size information enough?

**For scalars, yes, once three things change.** Constants become exact 64-bit patterns with no `AluOp` tag. Extensions become explicit operations. And whether a constant fits an immediate becomes a codegen decision, not a type. Together that removes D1, D2, D4, D5 and D6.

**For memory and pointers, no.** Correct compilation also needs the following. The analyses are side tables recomputed on demand and invalidated through the pass manager's `preserves`, not fields that passes must maintain.

1. **Slot types for ePass frame objects:** `SlotTy { size, align, may_hold_ptr }`. A slot that may hold a pointer is exactly 8 bytes, 8-aligned, and written only by `stxdw` from a register, never partially; that's the verifier's condition for tracking a spilled pointer. Spill slots are always this kind. Arrays are byte-addressed only through `getelemptr` on a slot.
2. **Stack provenance (an analysis):** `NotStack | Stack(off) | StackUnknown`. It's seeded by `FramePtr` and propagated through add/sub of constants and through phis (the same offset stays `Stack(off)`; anything else becomes `StackUnknown`). It determines the original frame extent (§6, frame).
3. **Value class (an analysis):** `Scalar | Ptr(Ctx | Stack | MapValue | Map | Unknown)`, plus nullability. It's seeded by `Param(1)`, map `ldsym`, and helper or kfunc return types from the facts view. Codegen uses it to never store a pointer via `st imm`, never spill a pointer into a non-pointer slot, never apply `zext32` to a pointer, and never fold a map `ldsym`. Instrumentation passes get the `is_nonptr` that `deprecated/core/passes/ecall.c` approximates by hand.
4. **Known zero-extension (an analysis):** used only by the `zext_elim` peephole (§6).
5. **Call signatures from the facts view:** argument count, which arguments are (pointer, size) memory pairs, return class, and optional arguments. These replace the 211-entry table in `helpers.rs`.
6. **Exact `ld_imm64` symbol kinds:** `imm64 | map_fd | map_idx | map_value_fd(off) | map_value_idx(off) | btf_id | func`. `func` (BPF_PSEUDO_FUNC) is rejected until subprograms are supported. Today's `VarAddr`/`CodeAddr` are really BTF_ID and FUNC, and FUNC's immediate is never relocated.

**Why not LLVM-style i32/i64 values with zext/trunc:** every eBPF 32-bit op reads the low half of a 64-bit register and zero-extends its result. Typed i32 values would turn each 32-bit instruction into a trunc/op/zext triple that codegen then has to pattern-match back together. Putting width on the op maps one-to-one to the ISA in both directions. A declared pointer type in submitted IR would also have to be trusted; derived facts don't.

### Instruction set

Semantics are defined over 64-bit values, per RFC 9669: shift amounts are masked, `x/0 = 0`, `x%0 = x`, and `INT_MIN/-1 = INT_MIN`.

```
bin.{w32,w64}   add sub mul udiv sdiv umod smod and or xor shl lshr ashr   ; w32 result = zext64(op32(lo a, lo b))
neg.{w32,w64}
zext32 / sext{8,16,32}.{w32,w64}   ; w1=w2 → zext32 ; r1=(s8)r2 → sext8.w64 ; w1=(s8)w2 → sext8.w32
bswap {width} {to_le | to_be | swap}          ; unifies end and v4 bswap; target endianness is in the environment
load {size} {zero|sign} [base + off16]        ; the addressing mode is preserved (ctx accesses need it)
store {size} [base + off16], value
ldsym {kind} imm                              ; see symbol kinds above
alloc SlotTy / slot_load / slot_store / getelemptr   ; ePass frame objects
call target=Helper(id) | Kfunc{btf_id, off} | Local(func), arity=Known(n) | Unknown
poison(imm)       ; libbpf-poisoned call, emitted verbatim, never returns
opaque {raw, def, uses, clobbers}   ; atomics, LD_ABS/IND: passed through, operands pinned to physical registers
ecall             ; reserved (see below)
phi, br, condbr.{w32,w64} {eq ne ugt uge ult ule sgt sge slt sle set} a, b -> T, F, ret v, throw
```

- **Branch targets are blocks.** There's no fallthrough-layout assumption in the IR.
- **`opaque` def/use/clobber sets must match the raw opcode exactly:**
  - LD_ABS/IND read r6 implicitly, clobber r1–r5 and define r0;
  - `BPF_FETCH` atomics define `src_reg`;
  - `CMPXCHG` reads and defines r0.

  The validator rejects any `opaque` whose sets disagree with its raw instruction.
- **`Module { funcs, entry }`** with per-function frames and `call.local`. Lifting subprograms is phase 2, but the data structure is phase 1, so nothing needs retrofitting.
- **Synthetic entry block.** The lifter always creates an entry block with no predecessors. The pc-0 block is ordinary and may carry phis, which fixes D10.
- **Reserved variants:** `Value::Builtin(kind)` (e.g. `BB_INSN_CRITICAL_CNT`, used by `test/pass/insn_counter_pass.c`) and `ecall`. `deprecated/core/passes/ecall.c` implements heap translation on it, and today's lifter accepts `src_reg = 6` calls. Both are in the IR and in the blob now, so adding them later doesn't need a format version bump.
  - v2 ports no pass that uses either.
  - `Builtin` resolves at emission; the logic already exists in `replace_builtin_consts` in `cg/norm.rs`.
  - The validator rejects `ecall` in submitted IR unless the policy allows it. An `ecall` that reaches Finalize with no lowering pass is `Error::Unsupported`.
- **Removed:**
  - `ConstKind::RawOff`/`RawOffRev`, which also fixes the `+sp` round-trip failure;
  - the CG-only IR kinds and values: `Reg`, `FunctionArg`, `Assign`, `VrPos`, `FlattenDst`.

  Post-allocation state lives in MIR (§6).

### Formats

- **`.epir` text** is the debugging format, userspace only. It must round-trip every dumpable function.
- **The binary blob** is the kernel input format and the stable ABI. It's little-endian, versioned, and contains: a header with counts and limits, then a function table, block table, instruction table with operand offsets, slot table and symbol table. It holds no strings and no pointers.
  - Every reference is an index, range-checked before anything is built.
  - Decoding is single-pass, non-recursive, and bounded by `max_insns`.
  - The kernel accepts only the blob. `epasstool` converts in both directions.

### IR validator (the security boundary)

Because the kernel accepts IR from userspace, the validator is a total function over bytes: it returns an error for any input and never panics. It checks:

- header and limits;
- operand counts and kinds per opcode;
- that every `Value::Insn` names a live, non-void instruction;
- that blocks are non-empty, end in exactly one terminator, and contain no other terminator;
- that phis sit at block heads with exactly one entry per predecessor;
- that the entry block has no predecessors;
- **that every def dominates its uses** (missing today in `check.rs`);
- that slot operations match their `SlotTy`;
- that `opaque` sets match the raw opcode;
- that `ecall` appears only when the policy allows it;
- that total frame size is at most 512 bytes.

It runs after load, after lifting, before codegen always, and after every pass in debug builds.

## 5. Lifter

- **Canonical constants:**
  - `mov64 K` and ALU64 K lift to `sext64(imm32)`;
  - `mov32 K` lifts to `zext64(imm32)`;
  - ALU32 K becomes the low 32 bits;
  - JMP K follows the jump's width.
- **New lifted ops:** JSET, MEMSX, MOVSX, sdiv/smod, ALU64 bswap and kfunc calls (with signatures from the facts view).
- **libbpf poison is recognized explicitly:** `0xbad2310`; `2001000000 + i` (a pair of identical calls); `2002000000 + i`. It lifts to `poison`.
- **Atomics and LD_ABS/IND lift to `opaque`.**
- **Unknown arity** (a non-poison helper id with no signature) is allowed **only in userspace**: every register in r1..r5 counts as used (undefined ones as `undef`), and the call is emitted unchanged. In the kernel, a non-poison id with no signature is a hard error.
- **`gotol`** (`JMP32|JA`, offset in imm32) lifts to an unconditional `br`. Block discovery and successor computation read `imm` instead of `off` for this form, and `relax` re-emits it as `ja` or `gotol` depending on range.
- **Everything else unsupported is a hard error:** `may_goto`, bpf-to-bpf calls in v2, and `BPF_PSEUDO_FUNC`. The catch-all that turns failures into no-ops (`lift.rs:399`) goes away. No instruction is created until the whole source instruction has been validated, which fixes D13.
- **trace_printk's optional arguments:** a register that's defined along every path is passed; otherwise the argument is `undef`. This replaces the current-block heuristic at `lift.rs:689`.
- **Iteration:** a reverse-postorder worklist, and Braun's lookup with an explicit stack, as in §3.

## 6. Code generation

Pipeline:

```
lower_throw → legalize → frame → liveness → allocate (spill, color, coalesce) → ssa_out → MIR → relax → encode
```

`encode` returns bytecode plus an old-to-new instruction offset map.

- **`lower_throw`** ports `translate_throw` as a mandatory Finalize pass. A `throw` becomes `ret <code>` after releasing outstanding ringbuf reservations, found with the existing gen/kill dataflow; the verifier rejects unreleased references. The return code is open question 3.
- **`legalize`** generalizes today's `spill_const`:
  - A 64-bit ALU op, a 64-bit JMP, or `st dw`, whose constant K doesn't satisfy `K == sext64(low32(K))`, gets the constant materialized into a register.
  - A 32-bit op takes any constant as `imm = low32(K)`.
  - Materialization uses `mov64 K` if the value fits sign-extended imm32, else `mov32 K` if it fits u32, else `lddw`.
  - Non-commutative first operands and constant-vs-constant compares are promoted to registers, as today.
  - **A constant left operand of a compare.** For `eq`/`ne`/`set`, the operands may be swapped at any ISA level. For an asymmetric compare, the operands may be swapped (reversing the condition, `swap_cond` at `cg/norm.rs:568`) only when the target is v2 or higher, because swapping turns v1 `jgt/jge/jsgt/jsge` into v2 `jlt/jle/jslt/jsle`. Below v2, the constant is materialized into a register instead.
  - Together this fixes D2 and D6.
- **`zext_elim`** is an Optimize-phase peephole, not part of legalize, and correctness doesn't depend on it. It drops `zext32` only when the source is one of:
  - a zero-extending load of 4 bytes or less;
  - a 32-bit ALU result;
  - a `zext32`;
  - a constant below 2^32;
  - a phi whose inputs all qualify.

  It **never** drops one after a sign extension, a sign-extending load, or a pointer. Everywhere else, `zext32` emits `mov32 wD, wS`, which fixes D1.
- **`frame`**: the original frame is never moved; `add_stack_offset` is deleted. The original extent `orig_depth` is the maximum of:
  - every dereference, counting `c + off + access size`;
  - every frame pointer passed as a memory argument by signature: `c` plus the size argument when that's constant, otherwise the whole stack;
  - the whole stack, if any frame pointer is stored to memory, escapes, or has an unknown offset.

  Round `orig_depth` up to a multiple of 8. Every ePass slot goes below it, and the total must be at most 512 bytes per function. `Error::Unsupported` is returned only when ePass actually needs frame slots, whether spill, scratch or pass-created ones. Fixes D9.
- **Register allocation** keeps the current allocator in v2: interference graph, maximum-cardinality search, pre-spill of oversized cliques, greedy coloring, post-spill fallback. It runs on the new iterative data structures and on MIR. Conditions:
  1. Register constraints are MIR facts: pre-colored copies into r1..r5 and out of r0 at calls, call clobbers, and "destination ≠ src2" for non-commutative ops. This keeps the allocator swappable behind the MIR interface.
  2. The post-allocation checker runs in all tests and debug builds.
  3. Exceeding the retry bound, or pre-spill's "oversized clique with no spillable value", returns `Error::RegAlloc`, never `Internal`, and follows the failure rules in §7.
  4. Phi interference is rederived after critical-edge splitting. Phi results interfere with each other and with values live out of each predecessor; phi operands are uses at the end of their predecessor. `phi_conflict_at_block` as written today goes away.
  5. The named phase-2 option is SSA-based allocation in dominance order (Hack and Goos), with a pressure model that counts src2 of a non-commutative op as live through the def. At a call, live-through values are at most 4 and copy sources at most 5, so a free register always exists for breaking copy cycles. At phi edges there's no such bound, so a scratch slot is needed there.
- **`ssa_out`**: critical edges into blocks with phis are split first. Then each edge's parallel copy is sequentialized; a cycle is broken through a free register at the edge, else an ePass scratch slot. XOR-swap is never used, since the verifier forbids it on pointers. Fixes D7 and D8.
- **MIR** is a separate lowered form: physical registers, slot offsets, immediates and labels. IR values are never mutated into codegen positions.
- **`relax`** orders blocks with today's fallthrough-chain heuristic (moved out of `cfg.rs`), inserts `ja` where a conditional's fallthrough isn't adjacent, and uses `ja32`/`gotol` when an offset exceeds i16 and the ISA level allows it; otherwise it's an error. Layout becomes an optimization rather than an IR invariant, which removes the "multiple chain predecessors" failures.
- **ISA gating:**
  - In the kernel, the host reports the ISA level the running kernel supports.
  - In userspace, the target defaults to the lowest level that covers every instruction in the input, overridable by gopt. ePass never emits an instruction above the target.
  - Apart from the swapped compare above, everything ePass introduces is v1: mov32/mov64 K and X, lddw, ja, ldx/stx, 64-bit lsh/arsh, call, exit.
  - Below v4:
    - sign-extending loads expand to `ldx; lsh64; arsh64`;
    - `sext*.w64` expands to `lsh64; arsh64`;
    - `sext8/16.w32` expands to `lsh64; arsh64; mov32 X`, because older kernels' verifiers reject 32-bit `arsh`;
    - an out-of-range branch is an error.
- **`encode`** range-checks every branch offset. It returns `old_index → new_index`, which the loader uses to remap `func_info`, `line_info` and `core_relos`, and which maps verifier diagnostics back to source instructions.
- **Post-allocation checker** (tests and debug builds) verifies:
  - no two simultaneously live values share a register;
  - every immediate is encodable;
  - the frame is at most 512 bytes;
  - branch offsets are in range;
  - simulating each parallel copy gives the same result as its sequentialization.

| Defect | Fixed by |
|---|---|
| D1 | `zext32` op; `zext_elim` limited to the proven cases |
| D2, D6 | exact constants plus the `legalize` encodability rules |
| D3 | `set` condition (folds as `a & b ≠ 0`; symmetric under operand swap) |
| D4, D5, D12 (sdiv) | `load … sign`, `sext*`, `sdiv`/`smod`, with ISA-gated expansions |
| D7, D8 | critical-edge split + parallel-copy sequentialization |
| D9 | frame placed below `orig_depth` |
| D10 | synthetic entry block |
| D11 | worklists, dataflow and iterative dominators |
| D12 (others), D13 | `opaque`, kfunc signatures, explicit poison, hard errors, no instruction created before validation |
| D14 | `lower_throw` |

## 7. Pass manager, policy and kernel integration

### Pass manager

- **Keep:** the `Pass` trait and the popt syntax.
- **Replace** string-list self-ordering (`register_pass` and the 32-iteration convergence loop in `pass.rs`) with declarative descriptors:

  `PassInfo { name, phase, after, before, default_on, user_controllable, preserves: [Analysis] }`

  - Phases are ordered `Canonicalize < Optimize < Instrument < Finalize`.
  - `Finalize` holds `lower_throw` and `legalize`, and is never user-controllable.
  - Enforcement passes sit in `Instrument`, so no user-controllable pass runs after them.
- **Order** is one topological sort of the static registry, checked acyclic by a unit test. Per-program options only filter it.
- **Analyses** are cached per function and invalidated by `preserves`.
- **Pipeline construction** takes `(loader popt, policy)` and returns the effective ordered list or `Error::Denied`.
- **Kernel-only passes** implement the same trait behind a feature flag, and are unit-tested in userspace against a mock facts view.

### Policy

A string in popt syntax, parsed by the same parser as popt:

- `+name(args)`: forced; always runs with these arguments, and the loader can't disable it;
- `-name`: denied;
- `name(args)`: allowed, with these as default arguments;
- plus a global `mode = off | optin | always`.

The effective pipeline is: forced passes, plus allowed passes the loader requests, plus passes that are on by default. The table below is the default rule, pending open question 2:

| Admin | Loader silent | Loader `name(args)` | Loader `!name` |
|---|---|---|---|
| forced | on, admin args | `-EPERM` | `-EPERM` |
| denied | off | `-EPERM` | off |
| allowed | default | on, loader args | off |

**Failure rules:**

- Bytecode input with only optional passes: an ePass error loads the original bytecode (fail open), and the ePass error still goes into `log_buf`.
- Any forced pass, or IR input: an ePass error rejects the load (fail closed).
- `mode = always` with no forced pass is best-effort by definition. "Forced" is the only enforcement bit.

### Kernel integration model (piece 2, interface level)

- **Flow.** In `bpf_prog_load`, after the instructions are copied in and the program type is resolved, and before `bpf_check`, the kernel calls ePass. Input is bytecode or a binary IR blob. Output is new bytecode plus the offset map. The glue reallocates the program, remaps `func_info`, `line_info` and `core_relos`, and then verification proceeds. The verifier stays the safety gate: an ePass bug can produce a rejected program, never an unsafe loaded one.
- **uapi.** New fields at the end of the `BPF_PROG_LOAD` attr:
  - pointer and length of an option string carrying gopt and popt;
  - pointer, length and format id for IR;
  - a `prog_flags` bit requesting ePass.

  When IR is supplied, `insn_cnt` must be 0. libbpf plumbs these fields from `bpf_prog_load_opts` and from the existing `LIBBPF_EPASS_*` environment variables. The userspace `epass_run` hook in patched libbpf stays as the mode for kernels without ePass.
- **Policy store.** A sysfs or sysctl string (piece 2 decides which).
- **Facts view.** Implemented in the kernel over verifier ops and BTF; in userspace over libbpf plus a table generated from the UAPI helper list. It provides:
  - program type;
  - ISA level;
  - helper prototype by id: arity, memory-argument pairs, return class, optional arguments;
  - kfunc prototype by BTF id;
  - map metadata by fd: type, key size, value size.
- **C ABI:**
  ```c
  int  epass_compile(const struct epass_host *h, const struct epass_facts *f,
                     const struct epass_policy *p, const struct epass_input *in,
                     struct epass_output *out);   /* out: insns, offset map, log */
  void epass_output_free(struct epass_output *out);
  /* -ENOMEM -EINVAL -EOPNOTSUPP -E2BIG -ENOSPC -EINTR -EPERM; an internal bug returns -EFAULT, never a panic */
  ```
- **Out of scope:** verifier-state-driven repair (the old `venv`/`check_apply` model in `deprecated/core/include/linux/bpf_ir.h`).

## 8. What stays from today's core

- Braun et al. SSA construction; the arena and typed-handle model; `IrBuilder` and the CFG edit helpers, reimplemented on the intrusive lists.
- The chordal-style allocator with post-spill fallback, as a MIR stage.
- The chain-layout heuristic, as a MIR stage.
- `const_prop`, `phi` and `optimize_ir`, rewritten against the new operation semantics. For example, `const_prop` folds with ISA shift masking.
- The `.epir` text format, with the new ops.
- popt syntax.

## 9. Design choices replaced

| Today | v2 | Why |
|---|---|---|
| `mov` always rebinds the SSA value | `mov32 X` is `zext32`; only `mov64 X` rebinds | D1 |
| `Value::Const { ty: AluOp, kind: RawOff… }` | exact 64-bit constants; no RawOff | D2, D6, D9 |
| Original frame shifted down, spills at the top | ePass area below the original frame | D9 |
| An untranslatable instruction becomes a warning and a no-op | `opaque`, kfunc signatures, explicit poison, or a hard error | D3, D5, D12, D13 |
| Entry block is the pc-0 block | synthetic entry block | D10 |
| Chain layout as an IR invariant checked after every pass | a MIR heuristic with `ja` insertion | fragile invariant, spurious internal errors |
| Sequential phi copies, no edge splitting | critical-edge split + parallel-copy sequentialization | D7, D8 |
| Recursive lifter and liveness | worklists and dataflow | D11, 16 KB kernel stacks |
| `Vec` per node, `HashMap` side tables, `contains` scans, linear `prev_insn` | chunked arenas, `IdxVec`, intrusive lists, sparse sets | 40 s at 50k insns; no `HashMap` in kernel Rust |
| `expect`/`assert!`/`unreachable!`; the C core's `CRITICAL()` → `panic()` | `Result` everywhere, checked accessors, clippy deny lints | a kernel panic is `BUG()` |
| Passes reorder a `Vec<String>` until it stops changing | declarative constraints and a topological sort | the convergence loop, opaque failures, policy determinism |
| CG-only variants inside `Value`; CG mutates the IR in place | separate MIR | stage leakage, unchecked invariants |
| CFG stored twice (succs lists + terminator targets); deduplicated user lists | successors derived from terminators; exact per-operand use lists | double bookkeeping |
| Hardcoded helper arity table (211 entries); kfuncs dropped | facts view + userspace-only unknown arity | brittleness, silent drops |
| Unbounded `String` log; the C core's 100 KB inline log in `bpf_ir_env` | host ring buffer into `log_buf` | kernel memory |
| C core: pointer-linked IR with a malloc per node, manual `env->err` checks, verifier state (`venv`) inside the core env | arenas, `Result`, a facts view | leaks and use-after-free on error paths; coupling |
| `prog_check` without dominance or operand-kind checks | the validator as a security boundary | untrusted IR input |

## 10. Testing decision

### Coverage and levels

1. **Semantic regression set**, end to end through `epasstool` and `epass-interp`, in `core-rs/epass-std/tests/semantic/`. 14 programs: D1–D10, D12-sdiv, D12-atomic (through `opaque`), D13 and D14 (through `.epir` with `throw`). D9 is made runnable with a test-only gopt `ra_colors=4`. Criterion: the interpreter result (r0, ctx bytes and stack bytes) is equal before and after ePass. Separately, bpf-to-bpf and `PSEUDO_FUNC` inputs must return `Error::Unsupported`.
2. **Differential generator.** Valid programs mixing ALU32/64, all conditions including JSET, JMP32, MEMSX/MOVSX, constant-offset stack traffic, stubbed helpers and bounded loops. 10,000 programs per CI run with a fixed seed, each run with `ra_colors` in {10, 6, 4}. Criterion: zero mismatches.
3. **Corpus.**
   - (a) The 339 Falco programs (the harness excludes `progs.txt`) and the bpftests compile.
   - (b) Stack invariant: every original direct stack offset and every r10-derived constant is unchanged, and ePass slots lie below `orig_depth`.
   - (c) With deterministic helper stubs, interpreter traces match: the same fault point or the same r0.
4. **Unit.**
   - containers under Miri;
   - lifter;
   - legalize;
   - the sequentializer over every arrangement of up to 5 registers, including cycles;
   - frame layout;
   - policy-table cases;
   - topological-sort acyclicity;
   - the validator on mutated blobs (must return `Err`, never panic);
   - `.epir` dump → load → dump identity on the 78-file corpus.
5. **Structural.**
   - the `no_std` build for `x86_64-unknown-none`;
   - clippy deny lints;
   - the whole `epass-core` suite, prog195 and a 120,001-block synthetic program, all inside a **16 KB thread**;
   - allocation failure injected at every allocation index for 6 programs (must return `OutOfMemory`, never panic, with 0 live allocations after drop);
   - a memory counter on prog195;
   - compile-time runs.

### Form

- `cargo test --release --workspace` runs 1–5, except Miri and fuzzing.
- `cargo +nightly miri test -p epass-core mem::`
- `cargo fuzz run blob_validator -- -runs=1000000`
- `cargo build -p epass-core --no-default-features --target x86_64-unknown-none`
- `cargo clippy -p epass-core -- -D clippy::indexing_slicing -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic`

### Passing and predictions

- **Regression set:** 14/14 equal. Today all 14 are red: 10 executed (D1–D8, D10, D13), D9 by the Falco static scan, and D12-sdiv, D12-atomic and D14 by code reading.
- **Differential:** 0 mismatches across 10,000 programs × 3 color counts. Today, any generated program with a negative `mov32 K`, a truncating `w = w` or a JSET mismatches, so we expect red within about the first 100 seeds. Confirm with one run.
- **Corpus (a):** the gate is at least 337/339, with no regression. We predict 339/339, because explicit poison handling is expected to fix prog195 and prog198. That's a prediction, not a gate.
- **Corpus (b):** 339/339. Today 16 programs fail (measured).
- **Corpus (c):** we predict 339/339. It's the least certain criterion, because it depends on how faithful the helper stubs are.
- **`.epir` round trip:** 78/78. Today 30 fail to load.
- **16 KB thread:** passes. Today the 120,001-block program aborts even on 8 MB.
- **Compile time:** a 200k-instruction straight-line program in under 5 s. Today that takes over 120 s, and 50k takes 40 s.
- **Memory:** peak under 300 bytes per input instruction on prog195, about 900 KB. This is the least certain number. The design bounds it at 1 KB per instruction, and `Limits` rejects anything over the budget.
- **Asserted, not predicted** (they follow from the code being written at all): Miri, the `no_std` build, clippy, allocation-fault injection, and 1,000,000 fuzz executions clean.

### How each criterion can be made to fail

| Criterion | Red configuration |
|---|---|
| Regression set | today's code (already observed red on 2026-09-30) |
| Sequentializer | emit copies in list order (reproduces D7) |
| Corpus (b) | re-enable frame relocation (reproduces D9) |
| Containers | an off-by-one in `Arena::get`, reported by Miri; run once and revert |
| Compile time | reintroduce `position()` in `prev_insn` |
| Fault injection | make one `try_push` infallible |
| Fuzz | remove the operand-index bounds check in the blob loader |
| Policy table | swap the precedence |

### Whether anything covers the deliverable

The mechanism being installed is semantic preservation. The break that disables it is lifting `mov32 X` as a rebind again.

- **Today:** the whole suite stays green under that break. `cargo test --release` passes with D1 present, which we observed.
- **After this work:** criteria 1 and 2 go red under the break, while 3–5 stay green, because Falco has no ALU32. So the corpus alone isn't a completion gate; 1 and 2 are.

### Edge cases

**Covered:**
- empty program;
- `exit` only;
- unreachable blocks;
- a phi with an `undef` input;
- a self-referencing phi;
- constant-only compares;
- K at both i32 boundaries and at 2^32;
- 512-byte frames;
- `ja32` distances;
- `max_insns` exactly and max+1;
- allocation failure at every index;
- a fatal signal (budget) injected through the userspace host.

**Not automated:**
- verifier acceptance and kernel behavior (see the procedure below);
- atomics beyond pass-through;
- concurrent loads under one policy change (piece 2).

### What only a person can check (about 2 h the first time)

1. Build ePass-kernel with `CONFIG_RUST=y` and the core, and boot it in a VM.
2. Load `test/output/progs_simple1.o` through the patched bpftool with default options. Confirm with `bpftool prog dump xlated`, and check that `line_info` is intact.
3. Set a policy forcing one pass. Confirm its effect. Then request that pass be disabled, and confirm `EPERM`.
4. Submit the same program as a binary IR blob.
5. Run the 70 programs listed in `CORRECT_PROGS` in `test/test.py`, plus Falco, with and without ePass. Confirm the set of accepted programs is unchanged.
6. Check dmesg: no warnings, no oops, no soft lockups.
7. Compare the kernel's output against userspace output, byte for byte, for 10 programs.

### Owed documents

- An acceptance procedure: `docs/lodestar/acceptance/2026-09-30-epass-v2-kernel-acceptance.md`.
- A measurement report (stack depth, peak memory, compile time, before and after): `docs/lodestar/reports/epass-v2-measurements.md`.

## 11. Non-goals

- Porting MSan, masking, the instruction counter, code compaction and the ecall passes from `test/pass/` and `deprecated/core/passes/`. This design only guarantees they're expressible: slot types, value class, `throw`, and the reserved `Builtin`/`ecall`.
- Lifting bpf-to-bpf calls and callbacks. That's phase 2; the `Module` structure is in phase 1.
- Atomic semantics beyond `opaque` pass-through.
- Verifier-state-driven repair.
- Upstream submission, 32-bit architectures, and JIT interaction.
- Dominance-order register allocation. That's a named phase-2 option (§6).
- Byte-identical output with the C core; register assignment will differ.

## 12. Open questions for the user

Both authors recommend the option marked "recommended" in each question.

1. **Kernel target.** Which kernel version does ePass-kernel track, and is a `CONFIG_RUST=y` build acceptable? The options are a built-in Rust object in `kernel/bpf/epass/` (recommended) or the freestanding staticlib fallback. If Rust isn't acceptable at all, switch to option 2.
2. **Policy conflicts.** When a loader requests a denied pass or disables a forced one: reject the load with `-EPERM` (recommended), or drop the request and log it? And may unprivileged loaders pass popt and IR, or only `CAP_BPF`?
3. **`throw` semantics.** The C core has two variants: `ret 1` (`translate_throw`) and `ret 0` plus ringbuf discard (`translate_throw_df`). Which is canonical? Or should the code be a pass argument, with one of those as the default?
4. **Kernel limits.** Default in-kernel `max_insns` of 65,536 and `max_bytes` of 64 MB, configurable by policy? Or is the full 1M-instruction range needed from day one?
5. **Failure default.** Fail open (load the original) for bytecode submissions with only optional passes (recommended), or always reject?
6. **Subprograms.** Is phase 2 for bpf-to-bpf lifting acceptable, with the `Module` structure in phase 1? Falco has none; `core-rs/bpftests/localcall.c` exists.
7. **IR text in the kernel.** Binary only, with text as a userspace debug format (recommended), or must the kernel also parse `.epir`?

## 13. Reconciliation record

Where the two drafts differed, and what was adopted:

| Topic | design0 | design1 | Adopted |
|---|---|---|---|
| Language | Rust no_std | Rust no_std | same |
| Host/containers | facade over the kernel crate's `KVVec` | host trait + own chunked containers | design1, with all containers chunked (design0's condition) |
| Kernel placement | `kernel/bpf/epass/` | `rust/kernel/epass/` | design0 (not inside the kernel crate) |
| Offset map, `func_info`/`line_info` remap | missing | present | design1, plus `core_relos` |
| Slot types, value class | provenance only | `SlotTy` + value class | design1 |
| Atomics, LD_ABS/IND | hard error | `opaque` | design1, with exact def/use/clobber sets validated (design0 + design1) |
| `zext32` elimination | not proposed | in legalize; "load ≤ 4 bytes" | design0's corrected rule, as an Optimize-phase peephole; design1's rule was wrong for sign-extending loads |
| Register allocator | keep current | Hack–Goos, "cannot fail" | design0 for v2. design1 retracted "cannot fail" (the pressure model missed src2 of non-commutative ops; r0 isn't always free at calls). Dominance-order allocation is phase 2 with design1's corrected model |
| Failure semantics | fail open / fail closed | missing | design0, plus design1's refinements |
| Time budget | `Budget` + `cond_resched` + fatal signal | limits only | design0 |
| ISA gating | yes | only `ja32` | design0; target = lowest level covering the input. design1 added the v2 rule for swapped compares (ePass's `swap_cond` emits v2 `jlt`-family instructions) and the `mov32`-after-64-bit-shift expansion for `sext*.w32` |
| `gotol` in the input | hard error | not addressed | design1's amendment: lift to `br` (reading imm32), re-emitted by `relax` |
| Stack extent | helper memory args + escapes | provenance only | design0, refined by design1: "+ access size" and constant size arguments |
| Builtin, `ecall` | cut | keep | design1 (reserved, validator-gated). The kmtest programs don't use `ecall`; the justification is `ecall.c` heap translation and `insn_counter_pass.c` |
| `throw` | `r0 = code; exit` | port `translate_throw` with ringbuf release | design1 |
| Post-allocation checker, exhaustive sequentializer tests, `preserves` | missing | present | design1 |
| Facts | 78 `.epir` files; Falco count given as 338 (wrong) | 80 `.epir` files, 340 Falco, 71 `CORRECT_PROGS`, "9 of 14 red", unknown helper "dropped" (all wrong) | corrected: 78; 339 programs + index; 70; 14 of 14 red; call kept without argument setup and exit lost |
| Stack-overflow evidence | none | `ulimit -s 16` on prog1 | 16 KB thread as the gate; `ulimit` is confounded (a 2-instruction program crashes 3 of 20) |

## Sign-off

- epass-94 (design0 author): agreed, 2026-09-30.
- Repository overview (2) (design1 author): agreed, 2026-09-30, subject to two amendments (ISA rule for swapped compares; lifting `gotol`), both applied in §5, §6 and §13.
