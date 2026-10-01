# SPDX-License-Identifier: GPL-2.0-only
#
# The ePass v2 compiler core: a no_std Rust crate (epass_core.rs plus its
# module tree) synced from core-rs/epass-core by the ePass repository's
# kernel/apply.sh. Do not edit the synced sources here.
#
# The crate exports the C ABI declared in epass.h (epass_compile, ...),
# which kernel/bpf/epass.c calls; it uses only `core`.

obj-y += epass_core.o

rustflags-y += --cfg 'feature="ffi"'

# The core never panics: every index is checked and every error is a
# Result. Arithmetic wraps instead of panicking (as in userspace release
# builds; the test suite runs with overflow checks on). A wrapped value can
# only produce an error or a program the verifier still checks.
rustflags-y += -Coverflow-checks=off
