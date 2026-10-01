# ePass in the kernel (Linux 7.2.y)

The kernel runs ePass inside `BPF_PROG_LOAD`, before the verifier.

- **Input.** Loaders submit bytecode with options, or ePass IR instead of bytecode.
- **Policy.** An administrator policy decides what runs.
- **Implementation.** The compiler is the same `core-rs/epass-core` source as in userspace, built into the kernel as a Rust object. The kernel side (`kernel/bpf/epass.c`) is plain C on top of the C ABI in `epass-core/include/epass.h`.

The kernel tree is the submodule **`third-party/ePass-kernel`**, branch `refactor/kernel` of [OrderLab/ePass-kernel](https://github.com/OrderLab/ePass-kernel). Its commits are:

| Commit | Contents |
|---|---|
| `Linux 7.2.8 (vanilla)` | the kernel.org 7.2.8 release, as the root commit |
| `bpf: uapi: ePass fields for BPF_PROG_LOAD` | `BPF_F_EPASS`, `epass_gopt`/`epass_popt`/`epass_ir` (kernel and `tools/` copies) |
| `bpf: run ePass in BPF_PROG_LOAD` | the `bpf_prog_load()` hook, line_info remap, verifier log, `bpf_epass_func_proto()`, `kernel/bpf/epass.c` (host, facts, policy sysctl, load glue), `include/linux/bpf_epass.h`, Kconfig/Makefile, `kernel/configs/epass.config` |
| `bpf: epass: sync core from ePass <rev>` | generated: the compiler crate `kernel/bpf/epass/epass_core.rs` and its modules, and `epass.h` |

Edit the kernel side directly in the submodule and commit there. The compiler itself is never edited in the kernel tree: change `core-rs/epass-core`, then sync it.

```bash
kernel/sync-core.sh                       # core-rs/epass-core -> third-party/ePass-kernel/kernel/bpf/epass/
git -C third-party/ePass-kernel commit -am "bpf: epass: sync core from ePass $(git log -1 --format=%h -- core-rs/epass-core)"
git -C third-party/ePass-kernel push       # then commit the new submodule pointer here
```

The sync makes these changes to the core:
- `lib.rs` becomes the crate root `epass_core.rs`, with the kernel lint allowances and the source revision;
- `epass.h` is copied alongside;
- the userspace-only text parser is dropped.

This repository's `kernel/` holds only `sync-core.sh` and `tests/`.

## Interface

**uapi** (`union bpf_attr`, `BPF_PROG_LOAD`):

| Field | Meaning |
|---|---|
| `prog_flags & BPF_F_EPASS` | request ePass (needed under `mode=optin` unless options are given) |
| `epass_gopt`, `epass_gopt_len` | global options, e.g. `verbose=2,isa=v4` (no NUL needed) |
| `epass_popt`, `epass_popt_len` | pass options, e.g. `!zext_elim`. Requires CAP_BPF |
| `epass_ir`, `epass_ir_len` | ePass binary IR instead of bytecode (`insn_cnt` must be 0). Requires CAP_BPF |

**Policy:** `/proc/sys/kernel/bpf_epass_policy`. Writing it requires CAP_SYS_ADMIN, and an invalid policy is refused. The default is `mode=optin`. Examples:

```bash
echo 'mode=optin' > /proc/sys/kernel/bpf_epass_policy        # only requested programs
echo 'mode=always,-zext_elim' > /proc/sys/kernel/bpf_epass_policy
echo 'mode=optin,+const_prop,user_popt=0,ir=0' > /proc/sys/kernel/bpf_epass_policy
```

The syntax and the precedence table are in [docs/v2/USAGE.md](../docs/v2/USAGE.md#administrator-policy).

**Behavior:**

- ePass runs after the program type is known, and before the LSM hook and the verifier. Both see the rewritten program.
- If ePass rewrites the program, `line_info` is remapped to the new instructions (sorted, one record per offset), and the ePass log is appended to the verifier log.
- On a fail-open error (bytecode input with optional passes only), the original program is loaded, and the log says why.
- IR input, forced passes, option errors and policy conflicts reject the load. Rejections before the verifier still copy the ePass log into `log_buf`.
- Programs with CO-RE relocations (`core_relo_cnt`) or several `func_info` records (bpf-to-bpf) keep their original instructions. With a forced pass they're rejected with `-EOPNOTSUPP`.
- Helper arities come from the verifier's own prototypes: arguments that are `ARG_DONTCARE` are not live. kfunc arities come from vmlinux BTF.
- **Resources.** Memory comes from `kvmalloc`, accounted to the loader's memcg. `cond_resched()` runs every 1024 work units, and a pending fatal signal aborts with `-EINTR`. Kernel limits apply: 65,536 input instructions, 64 MB, 10 s.
- **No panics in the Rust object.** It is built with `-Coverflow-checks=off`. Every index is checked, and errors are values.

## Build and boot (incus VM)

```bash
# one-time: the kernel tree and an Ubuntu VM
git submodule update --init third-party/ePass-kernel
sudo incus launch images:ubuntu/noble epass-vm --vm -c limits.cpu=16 -c limits.memory=16GiB \
     -c security.secureboot=false -d root,size=40GiB

# configure from the VM's own config, build packages
cd third-party/ePass-kernel
O=~/dev/linux/build-vm; mkdir -p $O
sudo incus exec epass-vm -- sh -c 'cat /boot/config-$(uname -r)' > $O/.config
sudo incus exec epass-vm -- lsmod > $O/../lsmod-vm
make LLVM=1 O=$O olddefconfig
yes '' | make LLVM=1 O=$O LSMOD=$O/../lsmod-vm localmodconfig
make LLVM=1 O=$O epass.config           # kernel/configs/epass.config
scripts/config --file $O/.config --set-str SYSTEM_TRUSTED_KEYS '' --set-str SYSTEM_REVOCATION_KEYS '' \
     --disable MODVERSIONS --set-str LOCALVERSION -epass --disable LOCALVERSION_AUTO
make LLVM=1 O=$O olddefconfig
make LLVM=1 O=$O -j$(nproc) bindeb-pkg     # $O/../linux-image-7.2.8-epass_*.deb

# install and boot it in the VM
sudo incus file push $O/../linux-image-7.2.8-epass_*_amd64.deb epass-vm/root/
sudo incus exec epass-vm -- sh -c 'dpkg -i /root/linux-image-7.2.8-epass_*.deb && reboot'
```

Notes:

- Host packages needed: `ovmf`, `qemu-system-modules-spice` (incus VMs), `debhelper`, `libdw-dev` (bindeb-pkg).
- On hosts that run Docker and firewalld, the VM gets no DHCP lease until `incusbr0` is in firewalld's trusted zone.
- `MODVERSIONS` is disabled because Rust requires `GENDWARFKSYMS` with it.

## Test

```bash
kernel/tests/build.sh /tmp/epass-selftest     # uapi headers from the submodule
sudo incus file push /tmp/epass-selftest/{epass_selftest,p1.blob} epass-vm/root/
sudo incus exec epass-vm -- /root/epass_selftest /root
```

The selftest checks:

- **Kernel and userspace agree.** It compares the verifier's view (xlated instructions) of a program compiled by ePass in the kernel with the userspace ePass output of the same program loaded without ePass. They agree exactly when the two compilers produce byte-identical output.
- **Bytecode and IR input**, plus a loop that stresses register allocation.
- **The verifier log** carries the ePass log.
- **Failures:** option errors, corrupt IR, and fail-open on bpf-to-bpf.
- **Every policy form:** off, always, forced, denied, `user_popt=0`, `ir=0`, and invalid policy strings.
