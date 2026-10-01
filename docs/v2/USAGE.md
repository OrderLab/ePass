# Using ePass v2

## Build

```bash
cd core-rs
cargo build --release          # epass-core, epasstool, libepass.a/.so
./scripts/check.sh             # every gate: tests, clippy, no_std, MSRV, C ABI
MIRI=1 ./scripts/check.sh      # also Miri on epass-core
```

Outputs:

- `target/release/epasstool`: the CLI.
- `target/release/libepass.a` and `libepass.so`: the C ABI for loaders. The header is `epass-core/include/epass.h`.

## epasstool

```text
epasstool <command> [options] <file>

read      lift, run passes and compile; write or print the result
print     print a program (bytecode as assembly, IR as .epir)
lift      lift bytecode to IR
convert   convert IR between .epir text and binary blob
```

**Inputs** are detected from the file contents:

- ELF objects (via libbpf; `-s <name>` selects one program);
- IR blobs (`EPIR` magic);
- dump files (one decimal `u64` per instruction, ending at the first blank line);
- `.epir` text.

**Options:**

| Option | Meaning |
|---|---|
| `--gopt <s>` | global options (below) |
| `--popt <s>` | pass options (below) |
| `--policy <s>` | administrator policy (below); the default is permissive |
| `-P` | `read`: run the passes only and output IR |
| `-s <name>` | the ELF program to process (default: all of them) |
| `-F <fmt>` | output format: `dump` (alias `log`), `raw` (alias `sec`), `asm`, `epir` or `blob`. The default comes from `-o`'s extension, otherwise `dump` for bytecode and `epir` for IR |
| `-o <file>` | write to a file instead of stdout |
| `-q` | don't print the compilation log (stderr) |

**Examples:**

```bash
T=core-rs/target/release/epasstool
$T read -s prog -o out.txt prog.o            # ELF -> dump
$T read -F asm prog.txt                      # dump -> assembly on stdout
$T print prog.o                              # disassemble without compiling
$T read -P --popt '!const_prop' prog.txt     # IR after the passes
$T read --gopt verbose=2 --popt dump_ir prog.txt   # IR in the log
$T lift prog.txt -o prog.epir                # bytecode -> IR text
$T convert prog.epir -o prog.blob            # text <-> blob
$T read prog.epir -o out.txt                 # compile IR text (or a blob)
```

Exit codes:

- 0 on success;
- 1 when compilation fails, including what a loader would treat as fail-open;
- 2 on a usage error.

## Global options (gopt)

Comma-separated `key` or `key=value`. An unknown key is an error.

| Key | Meaning | Default |
|---|---|---|
| `verbose=0..3` | log level: error, warn, info, debug | 1 (warn) |
| `isa=v1..v4` | code generation target, capped at the platform's level | the input's own level for bytecode; the platform's level for IR |
| `ra_colors=4..10` | registers available to the allocator (testing) | 10 |
| `throw_ret=N` | return value of a lowered `throw` | 0 |
| `check` / `nocheck` | post-allocation checker | on in debug builds |
| `verify_each` | validate the IR after every pass | on in debug builds |
| `endian=little\|big` | target byte order | the host's |

## Pass options (popt)

Comma-separated items:

- `name` or `name(args)` enables a pass (with arguments);
- `!name` disables it.

You never specify the order: it's fixed by each pass's phase and its after/before constraints.

| Pass | Phase | Default | Notes |
|---|---|---|---|
| `dump_ir` | canonicalize | off | prints the IR into the log at the info level (use `verbose=2`) |
| `const_prop` | optimize | on | exact constant folding (RFC 9669 semantics), branch folding |
| `phi` | optimize | on | removes trivial phis |
| `zext_elim` | optimize | on | drops `zext.32` of values whose upper half is already zero |
| `dce` | optimize | on | mark-and-sweep, including dead phi cycles and unreachable blocks |
| `lower_throw` | finalize | mandatory | `throw` → release outstanding ringbuf reservations, then `ret throw_ret` |

## Administrator policy

Comma-separated items:

| Item | Meaning |
|---|---|
| `mode=off\|optin\|always` | ePass never runs / runs when the loader asks or a pass is forced / runs on every program |
| `user_popt=0\|1` | loaders may pass popt |
| `ir=0\|1` | loaders may submit IR instead of bytecode |
| `ecall=0\|1` | allow ePass-internal calls in IR |
| `+name[(args)]` | force a pass |
| `-name` | deny a pass |
| `name(args)` | admin default arguments |

How the policy and the loader's popt combine:

| Admin | Loader silent | Loader `name(args)` | Loader `!name` |
|---|---|---|---|
| forced | on, with the admin's args | `-EPERM` | `-EPERM` |
| denied | off | `-EPERM` | off |
| allowed | default | on, with the loader's args | off |

**Failure:**

- Bytecode input where every pass is optional fails open: the original program is loaded and the error is logged.
- IR input, or any forced pass, fails closed: the load is rejected.
- An interrupt (a fatal signal in the kernel) always rejects.

## libbpf (userspace and kernel mode)

`third-party/ePass-libbpf` (branch `refactor/kernel`) links `libepass.a` and runs ePass in `bpf_object_load_prog` before each load:

```bash
cd third-party/ePass-libbpf/src && make -j     # builds core-rs/epass-capi too
sudo LIBBPF_ENABLE_EPASS=1 \
     LIBBPF_EPASS_GOPT='verbose=2' \
     LIBBPF_EPASS_POPT='!zext_elim' \
     LIBBPF_LOG_LEVEL=2 \
     ./my_loader prog.o
```

- `func_info` and `line_info` are remapped through ePass's offset map.
- With `LIBBPF_ENABLE_AUTORELOAD=1`, a verifier rejection of ePass's output retries with the original instructions and records.

**Kernel mode.** Add `LIBBPF_EPASS_KERNEL=1` and libbpf doesn't run ePass itself. It loads with `BPF_F_EPASS` and passes `LIBBPF_EPASS_GOPT`/`LIBBPF_EPASS_POPT` in the new `BPF_PROG_LOAD` fields. The kernel then runs ePass under its policy and remaps line_info itself; see [kernel/README.md](../../kernel/README.md).

- Programs can also set the options directly: `bpf_prog_load_opts` has `epass_gopt`, `epass_popt`, `epass_ir` and `epass_ir_len`.
- ePass-bpftool works in both modes through the same variables, e.g. `LIBBPF_ENABLE_EPASS=1 LIBBPF_EPASS_KERNEL=1 bpftool prog loadall prog.o /sys/fs/bpf/p`.

## Tests

| Where | What |
|---|---|
| `epass-core` unit tests | containers, the log, the sequentializer (exhaustive), the disassembler, … |
| `epass-std/tests/ir.rs` | construction, the validator, text and blob round trips, blob mutation, allocation failure |
| `epass-std/tests/lift.rs` | the lifter per opcode family, value facts, the counted-loop bound, all of Falco, a 120k-block CFG on a 16 KB stack |
| `epass-std/tests/passes.rs` | the policy table, pass order, every pass |
| `epass-std/tests/semantic.rs` | the interpreter oracle: the defect regression set, 10,000 random programs × `ra_colors` {10, 6, 4}, Falco (≥ 337/339, the frame invariant, no new uninitialized-register reads) |
| `epass-std/tests/structural.rs` | the whole pipeline on a 16 KB stack; allocation failure at every point; interrupt at every yield; heap, time and instruction limits; 200k instructions in under 5 s; memory |
| `epass-capi/tests/abi.rs` | the C ABI: dispositions, policy, IR input, facts callbacks, OOM sweep, leaks |
| `epass-capi/tests/c/smoke.c` | `epass.h` + `libepass.a` from C (run by `check.sh`) |
| `epasstool/tests/cli.rs` | every command and input kind, the Falco corpus, every `bpftests/*.c` built with clang |
