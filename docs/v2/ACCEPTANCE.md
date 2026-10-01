# ePass v2 acceptance (M8)

Date: 2026-09-30. Kernel: Linux 7.2.8 with ePass (OrderLab/ePass-kernel `refactor/kernel`, `7.2.8-epass+`, `CONFIG_BPF_EPASS=y`, clang 21 / `LLVM=1`), in an incus VM (Ubuntu noble, 16 vCPUs, 16 GiB). The raw results are in [acceptance-results.csv](acceptance-results.csv).

## Procedure

1. Build and boot the kernel in the VM ([kernel/README.md](../../kernel/README.md)).
2. Build the test tools on the host (all static). This produces:
   - `epass_selftest` and `p1.blob`;
   - `bpftool` (ePass-bpftool on ePass-libbpf);
   - `epass_logs`.

   ```bash
   kernel/tests/build.sh /tmp/tb        # uapi headers from third-party/ePass-kernel
   ```

3. Build the test objects. `vmlinux.h` must come from the VM's kernel.

   ```bash
   sudo incus exec epass-vm -- bpftool btf dump file /sys/kernel/btf/vmlinux format c > test/progs/vmlinux.h
   make -C test -k $(grep -oE '^output/[^:]+\.o' test/Makefile)
   cp test/progs/kernel_samples/*.o test/output/
   ```

4. In the VM, as root:

   ```bash
   ./epass_selftest .                                  # kernel ABI, policy, IR
   ./epass_selftest stress falco/prog*.txt             # in-kernel ePass on Falco
   ./acceptance.sh output/*.o > results.csv            # accepted sets, four modes
   LIBBPF_ENABLE_EPASS=1 LIBBPF_EPASS_KERNEL=1 LIBBPF_EPASS_GOPT=verbose=2 \
       ./epass_logs $(accepted objects)                # per-program ePass outcome
   dmesg | grep -iE 'BUG:|Oops|WARNING:|call trace'    # must be empty
   ```

`acceptance.sh` loads every object with `bpftool prog loadall` in four modes:

| Mode | How |
|---|---|
| base | no ePass |
| user | ePass in libbpf (`LIBBPF_ENABLE_EPASS=1`) |
| kernel | ePass in the kernel, requested by libbpf (`LIBBPF_EPASS_KERNEL=1`, which sets `BPF_F_EPASS`) |
| always | ePass in the kernel for an unmodified load (policy `mode=always`) |

## Results

**Accepted sets are unchanged** (the exit criterion):

| | base | user | kernel | always |
|---|---|---|---|---|
| objects accepted (of 111) | 81 | 81 | 81 | 81 |
| lost vs. base | — | 0 | 0 | 0 |
| gained vs. base | — | 0 | 0 | 0 |

- **CORRECT_PROGS** (`test/test.py`): 69 of the 70 objects build against 7.2's headers; `progs/libbpf/kprobe.bpf.c` uses a `struct filename` field that 7.2 renamed. All 69 are accepted in all four modes.
- The 30 objects rejected at base are rejected in every mode, for reasons unrelated to ePass:
  - the program itself fails verification (the `compile_speed` objects: "R2 invalid zero-sized read"; `libbpf_lsm`: return value out of range; deliberately unbounded loops);
  - the object is an old kernel sample whose section names libbpf 1.x can't map to a program type (`socket1`, `xdp_fwd`, …).

**ePass ran on every program.** The 81 accepted objects contain 121 programs. In-kernel ePass compiled all 121; none failed open, and all were then accepted by the verifier. `epass_logs` reads the ePass lines the kernel appends to each program's verifier log. Six objects can't be loaded by this simple loader, identically with and without ePass, so they're covered by the bpftool run only.

**Policy and ABI** (`epass_selftest`): 56 of 56 checks pass.

- **Byte-identity.** The kernel's ePass output is byte-identical to userspace ePass for the same input. The test compares the verifier's view (xlated instructions) of both. This was checked:
  - with default options, gopt (`verbose`, `isa=v1`, `ra_colors=4`) and popt;
  - on a loop program;
  - on IR-blob input.
- **Rejections that return `-EPERM`:**
  - a loader asks for a denied pass, or disables a forced one;
  - popt is sent under `user_popt=0`;
  - IR is sent under `ir=0` or `mode=off`.
- **`mode=off`** leaves requested programs untouched. **`mode=always`** and forced passes run ePass without a request.
- **Other errors.** Invalid policies are refused, and the policy is left unchanged. Bad gopt or popt returns `-EINVAL`, with the reason in `log_buf`. Corrupt IR is rejected.
- **Fail-open.** An unsupported program (bpf-to-bpf call) fails open: the original program loads, and the log says why.

**Falco** (`epass_selftest stress`, 339 programs plus the index file, loaded as raw tracepoints):

- In-kernel ePass compiles 337. The two callback programs and the index file fail open.
- The whole corpus takes about 0.6 s in the kernel.
- The programs' map fds are stale (they were captured elsewhere), so the verifier rejects most of them after ePass. This run checks the compiler, not acceptance.

**dmesg:** clean after every run. No BUG, Oops, WARNING or call trace.

## Measurements

Sizes are summed over the 81 objects accepted in all modes (121 programs), as reported by `bpftool prog show`:

| | xlated bytes | vs. base | JIT-ed bytes | vs. base |
|---|---|---|---|---|
| base | 54,136 | | 32,800 | |
| user (libbpf) | 54,208 | +0.13% | 33,229 | +1.31% |
| kernel / always | 53,440 | −1.29% | 32,882 | +0.25% |

Per object, kernel ePass versus base (xlated):

| Smaller | Unchanged | Larger |
|---|---|---|
| 38 objects (best: `counter_loop3` −54%, `msan1` −33%, `mask` −30%) | 24 objects | 19 objects (worst: `tengjiang_xdp` +29%, `complex2` +14%) |

**Kernel versus userspace.** Kernel ePass produces smaller code than userspace ePass on the same objects because its facts are better. Helper arities come from the verifier's own prototypes: arguments that are `ARG_DONTCARE`, such as `trace_printk`'s format arguments, aren't live. Userspace uses ePass's built-in table, which keeps optional arguments live.

**Where ePass grows code.** The inputs are clang `-O2` output. The largest growth is a return value that is the same constant on many paths, e.g. `w0 = 2` set once at entry, then several early `goto exit`. SSA turns it into `phi(2, 2, 2, 2, 1)`, and SSA-out materializes the constant on every incoming edge. Hoisting repeated constant phi inputs into a dominator would remove this. That's the next codegen item; correctness is unaffected.

## Not covered

- **Unsupported programs fail open** and load unchanged:
  - bpf-to-bpf calls and callbacks (`BPF_PSEUDO_FUNC`);
  - module kfuncs (`fd_array`).
- **CO-RE.** In kernel mode, programs that carry `core_relos` in `BPF_PROG_LOAD` keep their original instructions; these are light skeletons, since normal libbpf applies CO-RE in userspace. With a forced pass they're rejected with `-EOPNOTSUPP`.
- **Option keys.** The old harness's gopt `cgv2` is a v1 option and is invalid in v2 (`-EINVAL`). Use the v2 keys in [USAGE.md](USAGE.md#global-options-gopt).
