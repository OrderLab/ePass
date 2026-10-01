#!/usr/bin/env bash
# Sync core-rs/epass-core into a kernel tree as the built-in Rust crate
# kernel/bpf/epass/ (epass_core.rs plus its module tree and epass.h).
# The kernel side (glue, hooks, Kconfig, kernel/bpf/epass/Makefile) lives
# in the ePass-kernel repository, the submodule third-party/ePass-kernel.
#
#   kernel/sync-core.sh [kernel tree]     (default: third-party/ePass-kernel)
#
# Then commit the result in the kernel tree, e.g.
#   git -C third-party/ePass-kernel commit -am "bpf: epass: sync core from ePass <sha>"
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
core="$repo/core-rs/epass-core"
tree="$(cd "${1:-$repo/third-party/ePass-kernel}" && pwd)"
dst="$tree/kernel/bpf/epass"

[ -f "$dst/Makefile" ] || { echo "$tree has no kernel/bpf/epass/Makefile (not an ePass kernel)" >&2; exit 1; }
# The last ePass commit that changed the core (stable across unrelated commits).
rev="$(git -C "$repo" log -1 --format=%h -- core-rs/epass-core 2>/dev/null || echo unknown)"
if [ -n "$(git -C "$repo" status --porcelain -- core-rs/epass-core 2>/dev/null)" ]; then
  rev="$rev-dirty"
fi

find "$dst" -mindepth 1 -maxdepth 1 ! -name Makefile -exec rm -rf {} +
cp -r "$core/src/." "$dst/"
rm -f "$dst/ir/parse.rs"           # `text` feature: userspace only
cp "$core/include/epass.h" "$dst/epass.h"
spdx='// SPDX-License-Identifier: GPL-2.0-only'
while IFS= read -r -d '' f; do
  { echo "$spdx"; cat "$f"; } > "$f.tmp" && mv "$f.tmp" "$f"
done < <(find "$dst" -name '*.rs' ! -name lib.rs -print0)
{
  echo "$spdx"
  echo "//! GENERATED from the ePass repository (core-rs/epass-core, $rev) by"
  echo "//! kernel/sync-core.sh. Do not edit; change epass-core instead."
  # Kernel lints the core is not written against (it has its own, stricter,
  # set: no panics, no indexing, no unwrap; see core-rs/epass-core/Cargo.toml).
  echo '#![allow(missing_docs, unreachable_pub, rust_2018_idioms, dead_code)]'
  echo '#![allow(clippy::all, clippy::undocumented_unsafe_blocks, clippy::ptr_as_ptr)]'
  echo '#![allow(clippy::cast_lossless, clippy::as_underscore, clippy::ref_as_ptr)]'
  echo '#![allow(clippy::ptr_cast_constness, clippy::as_ptr_cast_mut)]'
  grep -v '^#!\[no_std\]$' "$dst/lib.rs"   # kbuild adds no_std itself
} > "$dst/epass_core.rs"
rm "$dst/lib.rs"
echo "synced epass-core $rev into $dst"
