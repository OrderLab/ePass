#!/usr/bin/env bash
# Structural gates for the v2 core. Run from anywhere; exits non-zero on the
# first failing gate. Set MIRI=1 to also run Miri on epass-core.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$*"; }

step "tests (release)"
cargo test --release --workspace --quiet

step "clippy: no-panic lints on epass-core, then the workspace"
cargo clippy -p epass-core --all-targets --features text,ffi -- -D warnings
cargo clippy --workspace --all-targets -- -D warnings

step "no_std build (x86_64-unknown-none)"
cargo build -p epass-core --target x86_64-unknown-none --quiet
cargo build -p epass-core --target x86_64-unknown-none --features text --quiet
cargo build -p epass-core --target x86_64-unknown-none --features ffi --quiet

if rustup toolchain list | grep -q '^1.85'; then
  step "MSRV 1.85 (Linux 7.2 minimum rustc)"
  cargo +1.85 build -p epass-core --target x86_64-unknown-none --features ffi --quiet
fi

step "C ABI: epass.h + libepass.a smoke test"
smoke="$(mktemp -d)/smoke"
cc -std=c11 -Wall -Wextra -Werror -I epass-core/include epass-capi/tests/c/smoke.c \
  target/release/libepass.a -lpthread -ldl -lm -o "$smoke"
"$smoke"

if [ "${MIRI:-0}" = 1 ]; then
  step "miri"
  cargo +nightly miri test -p epass-core
fi

printf '\nall gates passed\n'
