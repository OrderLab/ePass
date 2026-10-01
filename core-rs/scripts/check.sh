#!/usr/bin/env bash
# Structural gates for the v2 core. Run from anywhere; exits non-zero on the
# first failing gate. Set MIRI=1 to also run Miri on epass-core.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$*"; }

step "tests (release)"
cargo test --release --workspace --quiet

step "clippy: no-panic lints on epass-core"
cargo clippy -p epass-core --all-targets -- -D warnings

step "no_std build (x86_64-unknown-none)"
cargo build -p epass-core --target x86_64-unknown-none --quiet

if rustup toolchain list | grep -q '^1.85'; then
  step "MSRV 1.85 (Linux 7.2 minimum rustc)"
  cargo +1.85 build -p epass-core --target x86_64-unknown-none --quiet
fi

if [ "${MIRI:-0}" = 1 ]; then
  step "miri"
  cargo +nightly miri test -p epass-core
fi

printf '\nall gates passed\n'
