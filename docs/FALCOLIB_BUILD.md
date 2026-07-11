# Falcolib Scap and Probe Build Notes

Date: 2026-07-11

Workspace: `/home/ubuntu/Downloads/ePass`

## Goal

Build `third-party/ePass-falcolib` scap userspace, both BPF probe variants where possible, and the small tools used to exercise the probes.

## Host Prerequisites Observed

- Ubuntu kernel: `6.8.0-134-generic`
- Kernel headers: `/lib/modules/6.8.0-134-generic/build`
- Kernel BTF: `/sys/kernel/btf/vmlinux`
- CMake: `3.28.3`
- GCC: `13.3.0`
- Clang: `22.1.8`
- bpftool: `v7.4.0`
- `llc` was not installed as an unversioned binary, but `/usr/bin/llc-22` was available.

Additional packages installed while testing:

```bash
sudo -n apt-get install -y libcap-dev
```

`libpcap-dev` was also installed earlier while validating xdp-tools.

## Relevant Source Changes

Falcolib's bundled libbpf dependency was changed in `third-party/ePass-falcolib/cmake/modules/libbpf.cmake`:

```cmake
GIT_REPOSITORY "git@github.com:OrderLab/ePass-libbpf.git"
GIT_TAG "rs"
```

The same CMake module now passes the repository root Rust ePass path into the cloned libbpf build:

```cmake
EPASS_RS_DIR=${PROJECT_SOURCE_DIR}/../../core-rs
```

Without that, the `rs` libbpf build fails at `#include "epass.h"` because the cloned libbpf cannot infer the parent ePass repository layout.

The configured build verified that bundled libbpf was cloned from branch `rs`:

```bash
git -C build-scap-drivers/libbpf-prefix/src/libbpf rev-parse --abbrev-ref HEAD
# rs
git -C build-scap-drivers/libbpf-prefix/src/libbpf rev-parse HEAD
# 31b632bc5a06a663aecaf5e936977e78bc4c4766
```

## Configure

Used the repository preset that enables scap, modern BPF, legacy BPF, kmod, and driver/libscap test targets:

```bash
cd third-party/ePass-falcolib
cmake --preset scap-drivers
```

Important preset options:

```text
USE_BUNDLED_DEPS=ON
BUILD_LIBSCAP_MODERN_BPF=ON
BUILD_BPF=ON
BUILD_DRIVER=ON
CREATE_TEST_TARGETS=ON
ENABLE_DRIVERS_TESTS=ON
ENABLE_LIBSCAP_TESTS=ON
BUILD_LIBSCAP_GVISOR=OFF
```

## Build Commands

Modern BPF skeleton and scap:

```bash
cmake --build build-scap-drivers --target ProbeSkeleton scap -j$(nproc)
```

Legacy BPF probe:

```bash
cmake --build build-scap-drivers --target bpf -j$(nproc) -- LLC=/usr/bin/llc-22
```

The explicit `LLC=/usr/bin/llc-22` is needed on this host because the legacy BPF Makefile defaults to `llc`, and only the versioned LLVM tool is installed.

Runtime/example and test tools:

```bash
cmake --build build-scap-drivers --target scap-open drivers_test libscap_test driver -j$(nproc) -- LLC=/usr/bin/llc-22
```

## Build Results

All requested targets built successfully after passing `LLC=/usr/bin/llc-22` and installing `libcap-dev`.

Artifacts:

```text
build-scap-drivers/libscap/libscap.a                         235K
build-scap-drivers/skel_dir/bpf_probe.skel.h                 8.3M
build-scap-drivers/driver/modern_bpf/bpf_probe.o             2.8M
build-scap-drivers/driver/bpf/probe.o                        5.7M
build-scap-drivers/driver/src/scap.ko                        3.7M
build-scap-drivers/libscap/examples/01-open/scap-open         13M
build-scap-drivers/test/drivers/drivers_test                  64M
build-scap-drivers/test/libscap/libscap_test                  24M
```

Notes:

- Modern BPF built successfully and generated `skel_dir/bpf_probe.skel.h`.
- `scap` built successfully with the modern BPF engine bundled.
- Legacy BPF built successfully as `driver/bpf/probe.o` when `LLC=/usr/bin/llc-22` was supplied.
- Kmod built successfully as `driver/src/scap.ko`; the build printed `Skipping BTF generation ... due to unavailability of vmlinux`, but still produced the module.
- The legacy BPF configure probe `TASK_PIDS_FIELD` failed because this kernel's `struct task_struct` lacks `pids`; this is expected feature detection and did not fail the final probe build.

## Probe Test Tools

Built `scap-open`, the small libscap example used to load and test drivers:

```bash
build-scap-drivers/libscap/examples/01-open/scap-open --help
```

Supported source options from its help output:

```text
--kmod
--bpf <probe_path>
--modern_bpf
--scap_file <file.scap>
```

Typical local smoke commands, run with privileges because loading probes/modules requires kernel capabilities:

```bash
sudo ./build-scap-drivers/libscap/examples/01-open/scap-open \
  --modern_bpf --num_events 10 --verbose 6

sudo ./build-scap-drivers/libscap/examples/01-open/scap-open \
  --bpf ./build-scap-drivers/driver/bpf/probe.o --num_events 10 --verbose 6

sudo ./build-scap-drivers/libscap/examples/01-open/scap-open \
  --kmod --num_events 10 --verbose 6
```

Also built the broader driver test harness:

```bash
sudo ./build-scap-drivers/test/drivers/drivers_test -m
```

I only built these tools and inspected their help. I did not run the probe-loading smoke tests here because they attach kernel probes/modules and can perturb the host.
