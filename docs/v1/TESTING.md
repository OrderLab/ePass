# Testing

## Rust unit/integration tests

```bash
cd core-rs
cargo test --release
```

The current tests cover:

- bytecode packing/unpacking;
- lifter basics;
- compile/codegen basics;
- IR text dump/load;
- `IrBuilder`;
- CFG utility helpers.

## Dump-format roundtrip

The dump format is one packed `u64` per BPF instruction.

```bash
core-rs/target/release/epasstool read -F log -o out.txt input.txt
```

## EPIR corpus

Parseable IR dumps for sample programs live under:

```text
core-rs/epass-ir/tests/epir
```

Regenerate them from `test/output/*.o` with the `dump_ir` pass:

```bash
cd test/output
EP=../../core-rs/target/release/epasstool
OUT=../../core-rs/epass-ir/tests/epir
mkdir -p "$OUT"
for obj in *.o; do
  for fn in $(readelf -sW "$obj" | awk '$4=="FUNC"{print $8}' | sort -u); do
    safe=$(printf '%s__%s' "${obj%.o}" "$fn" | tr '/:' '__')
    "$EP" read -P --popt "dump_ir($OUT/$safe.epir)" --gopt verbose=0 -s "$fn" "$obj" || true
  done
done
```

Some ELF `FUNC` symbols are not libbpf programs and will be skipped.

## Verifier testing through patched libbpf

Build patched bpftool:

```bash
cd third-party/ePass-bpftool/src
make -j
```

Load through ePass:

```bash
sudo LIBBPF_ENABLE_EPASS=1 \
     third-party/ePass-bpftool/src/bpftool prog load test/output/progs_simple1.o /sys/fs/bpf/test
sudo rm -f /sys/fs/bpf/test
```

Use a timeout for batch testing because some sample programs or attach types can
hang/fail independently of ePass:

```bash
timeout -k 2 15 sudo LIBBPF_ENABLE_EPASS=1 ...
```

For meaningful comparisons, first check whether the original program loads
without ePass; only baseline-loadable programs should be counted as verifier
regressions.

## Old C core comparison

The old C core under `core/` can still be built and used as a reference, but it
is no longer the active implementation.

```bash
cd core
make configure
make build
```

The Rust implementation is expected to be verifier-correct, but byte-for-byte
identity with the old C code is not guaranteed for all programs because register
allocation and cleanup passes can choose different but equivalent bytecode.
