#!/usr/bin/env bash
# Build the in-VM selftest: a static binary linking core-rs libepass.a, plus
# the IR blob it loads. Needs the patched uapi headers of the kernel tree:
#   kernel/tests/build.sh <kernel tree> <out dir>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
tree="$(cd "${1:?kernel tree}" && pwd)"
out="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"

make -s -C "$tree" O="$out/hdr-build" headers_install INSTALL_HDR_PATH="$out/hdr" >/dev/null
cargo build -q --release --manifest-path "$root/core-rs/Cargo.toml" -p epass-capi -p epasstool
cc -O2 -Wall -Werror -static -I "$out/hdr/include" -I "$root/core-rs/epass-core/include" \
  "$here/epass_selftest.c" "$root/core-rs/target/release/libepass.a" -lpthread -ldl -lm \
  -o "$out/epass_selftest"

# p1 from epass_selftest.c as a dump file, lifted to an IR blob.
python3 - "$out/p1.txt" <<'PY'
import sys
def ins(code, dst=0, src=0, off=0, imm=0):
    return code | dst << 8 | src << 12 | (off & 0xffff) << 16 | (imm & 0xffffffff) << 32
p1 = [ins(0x85, imm=7), ins(0xb7, 2, imm=5), ins(0xb7, 3, imm=7), ins(0x2f, 2, 3),
      ins(0x7b, 10, 2, -8), ins(0x79, 4, 10, -8), ins(0x0f, 0, 4), ins(0x25, 0, off=1, imm=1000),
      ins(0xb7, 0), ins(0x95)]
open(sys.argv[1], "w").write("".join(f"{x}\n" for x in p1))
PY
"$root/core-rs/target/release/epasstool" lift -q "$out/p1.txt" -o "$out/p1.blob"
echo "built $out/epass_selftest and $out/p1.blob"
