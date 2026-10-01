# ePass v2 C ABI

Header: `core-rs/epass-core/include/epass.h`. Implemented in `epass-core/src/ffi.rs` (feature `ffi`).

The kernel glue and userspace loaders use the same entry point. Userspace links `libepass.a` from `core-rs/epass-capi`, which also provides `epass_default_host()` over malloc.

```c
int  epass_compile(const struct epass_host *host, const struct epass_facts *facts,
                   const struct epass_policy *policy, const struct epass_input *in,
                   struct epass_output *out);
void epass_output_free(struct epass_output *out);
```

```c
int epass_policy_check(const struct epass_host *host, const char *str, u32 len);
```

`epass_policy_check` validates a policy string and summarizes it. It returns the mode (`EPASS_MODE_OFF`, `_OPTIN` or `_ALWAYS`, masked by `EPASS_POLICY_MODE_MASK`) together with the flags `EPASS_POLICY_FORCED`, `EPASS_POLICY_IR` and `EPASS_POLICY_USER_POPT`, or a negative errno. The kernel calls it when the sysctl is written, and uses the summary to skip `epass_compile` for programs ePass would not touch.

## Return value

| Return | Meaning | `out` |
|---|---|---|
| `0` | load ePass's output | `insns`, `insn_cnt` and `offsets` (bytecode input) are set |
| `1` | load the original program | `error` is 0 when ePass didn't run (policy), otherwise the negative errno of the fail-open error |
| `< 0` | reject the load with this errno | — |

`out->log` holds the compilation log in every case: NUL-terminated, `log_len` bytes excluding the NUL, or NULL. Always call `epass_output_free(out)`. It's safe on a zeroed or already-freed output.

Errors:

- `-ENOMEM`: the host allocator failed.
- `-E2BIG`: a limit was hit (instructions, heap bytes, time).
- `-EINTR`: `should_yield` asked to stop.
- `-EOPNOTSUPP`: an unsupported input feature, e.g. bpf-to-bpf calls or callbacks.
- `-EINVAL`: malformed input, options or IR.
- `-ENOSPC`: register allocation or stack space failed.
- `-EPERM`: the policy forbids the request.
- `-EFAULT`: an internal invariant failed (an ePass bug). ePass never crashes.

## Structures

**`epass_host`**

- `alloc(ctx, size, align)` returns NULL on failure; `size` is never 0.
- `free(ctx, ptr, size, align)`.
- Optional:
  - `log(ctx, level, msg, len)` for immediate diagnostics;
  - `now_ns(ctx)` for the time limit;
  - `should_yield(ctx)`, which is called every `yield_every` work units and returns nonzero to abort with `-EINTR`. The kernel host calls `cond_resched()` here and checks `fatal_signal_pending()`.

Output buffers are allocated through the same host. `out->host` remembers it, so it must stay valid until `epass_output_free`.

**`epass_facts`** (NULL = userspace defaults: ISA v4, the built-in helper table, unknown calls accepted)

- `isa`: the highest ISA level the platform accepts (1..4; 0 means 4).
- `flags`: `EPASS_FACTS_UNKNOWN_CALLS` accepts calls of unknown signature, assuming r1..r5 are live. This is userspace only; the kernel always knows its helpers.
- `helper(ctx, id, sig)` and `kfunc(ctx, btf_id, fd_idx, sig)` return 0 and fill `struct epass_sig { nargs, optional_from, ret }`, or nonzero for unknown.
  - A NULL `helper` callback uses ePass's built-in table (ids 1..211).
  - A NULL `kfunc` callback knows no kfuncs.
  - `ret` is one of `EPASS_RET_SCALAR`, `_MAP_VALUE_OR_NULL`, `_MEM_OR_NULL`, `_PTR`.

**`epass_policy`** (NULL = permissive userspace policy and userspace limits)

- `str`/`len`: the policy string (see [USAGE.md](USAGE.md#administrator-policy)).
- `preset`: `EPASS_PRESET_USER` or `EPASS_PRESET_KERNEL`.

| Limit | Kernel preset | User preset |
|---|---|---|
| `max_insns` | 65,536 | 1,000,000 |
| `max_bytes` | 64 MB | 4 GB |
| `time_ns` | 10 s | none |
| `log_bytes` | 64 KB | 1 MB |

A zero field takes the preset's value.

**`epass_input`**

- `insns`/`insn_cnt` (bytecode, bit-compatible with `struct bpf_insn`) or `ir`/`ir_len` (a binary IR blob), never both.
- `gopt`/`gopt_len` and `popt`/`popt_len`: option strings. They don't need to be NUL-terminated and may be NULL with length 0.
- `flags`: `EPASS_IN_REQUESTED` says the loader asked for ePass (this matters under `mode=optin`).

**`epass_output`**

- `insns`, `insn_cnt`.
- `offsets`, `offsets_cnt`: `offsets_cnt == insn_cnt_in + 1`. `offsets[i]` is the output index of original instruction slot `i`.
  - Removed instructions map to the next surviving one.
  - `offsets[0] == 0` and `offsets[insn_cnt_in] == insn_cnt`.
  - The map is **not monotonic** in general, because block layout may reorder code. A loader remapping `line_info` (which must be strictly increasing) sorts by the new offset and keeps one record per offset; see `epass_remap_recs` in ePass-libbpf.
  - `core_relos` targets must not be rewritten by passes. Kernel glue that sees `core_relos` keeps the original program.
- `log`, `log_len`, `error`.

## Example (userspace)

```c
#include "epass.h"

struct epass_input in = {
	.insns = (const struct epass_insn *)insns, .insn_cnt = cnt,
	.gopt = "verbose=2", .gopt_len = 9,
	.flags = EPASS_IN_REQUESTED,
};
struct epass_output out;
int rc = epass_compile(epass_default_host(), NULL, NULL, &in, &out);
if (rc == 0)
	use(out.insns, out.insn_cnt, out.offsets);
else if (rc < 0)
	reject(rc);
/* rc == 1: load the original */
if (out.log)
	fputs(out.log, stderr);
epass_output_free(&out);
```

Build: `cc ... -I core-rs/epass-core/include core-rs/target/release/libepass.a -lpthread -ldl -lm`.
