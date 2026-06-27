# Userspace Testing

The active userspace implementation is `core-rs`. The old C `core/` is kept as
reference.

## Build Rust core and CLI

```bash
cd core-rs
cargo build --release
cargo test --release
```

The CLI binary is:

```text
core-rs/target/release/epasstool
```

## Basic CLI usage

```bash
# Rewrite an ELF program and write dump-format output.
core-rs/target/release/epasstool read -s prog -F log -o out.txt test/output/progs_simple1.o

# Print original BPF in dump format.
core-rs/target/release/epasstool print --gopt print_dump test/output/progs_simple1.o

# Dump lifted IR before passes.
core-rs/target/release/epasstool read -P --popt 'dump_ir(/tmp/prog.epir)' -s prog test/output/progs_simple1.o

# Load IR instead of lifting bytecode.
core-rs/target/release/epasstool read --gopt load_ir=/tmp/prog.epir -F log -o out.txt dummy.txt
```

See [EPASS_OPTIONS.md](EPASS_OPTIONS.md) for `--gopt` and `--popt`.

## Patched libbpf

`third-party/ePass-libbpf` is patched to call ePass before program load when
`LIBBPF_ENABLE_EPASS=1` is set.

Build:

```bash
cd third-party/ePass-libbpf/src
make -j
```

This builds both `libbpf.a` and `libbpf.so`. The static archive includes the
Rust C ABI library `libepass_ir.a`.

## Patched bpftool

Many system bpftool builds are statically linked, so build the repository copy:

```bash
cd third-party/ePass-bpftool/src
make -j
```

Load a program through ePass and the kernel verifier:

```bash
sudo LIBBPF_ENABLE_EPASS=1 \
     LIBBPF_EPASS_GOPT='verbose=1' \
     third-party/ePass-bpftool/src/bpftool prog load test/output/progs_simple1.o /sys/fs/bpf/test
```

Clean up:

```bash
sudo rm -f /sys/fs/bpf/test
```

To prove the rewritten program was loaded, compare kernel `xlated` size:

```bash
sudo third-party/ePass-bpftool/src/bpftool prog show pinned /sys/fs/bpf/test
```

## Dynamic libbpf consumers

Any application dynamically linked against libbpf can use the patched shared
library by setting `LD_LIBRARY_PATH` to `third-party/ePass-libbpf/src`, then
setting `LIBBPF_ENABLE_EPASS=1`.

## Useful environment variables

| Variable | Meaning |
|----------|---------|
| `LIBBPF_ENABLE_EPASS=1` | Enable ePass rewrite before load. |
| `LIBBPF_EPASS_GOPT='...'` | Global options passed to ePass. |
| `LIBBPF_ENABLE_AUTORELOAD=1` | If rewritten load fails, retry original instructions. |

Pass options are currently CLI-side (`--popt`) for `epasstool`. The libbpf C ABI
uses the default pass pipeline unless extended to pass popt separately.
