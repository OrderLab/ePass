/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ePass v2 C ABI.
 *
 * One entry point compiles one eBPF program (bytecode or a binary IR blob)
 * under an administrator policy. The same ABI is used by the kernel glue
 * (kernel/bpf/epass.c) and by userspace loaders linking libepass.a.
 *
 *     struct epass_output out;
 *     int rc = epass_compile(&host, &facts, &policy, &in, &out);
 *     if (rc == 0)       use out.insns / out.insn_cnt (and out.offsets)
 *     else if (rc == 1)  load the original program (out.error says why, 0 = ePass did not run)
 *     else               reject the load with rc (a negative errno)
 *     ... out.log holds the compilation log in every case ...
 *     epass_output_free(&out);
 *
 * Errors: -ENOMEM -EINVAL -EOPNOTSUPP -E2BIG -ENOSPC -EINTR -EPERM; an
 * internal bug returns -EFAULT, never a crash.
 */
#ifndef _EPASS_H
#define _EPASS_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u8 epass_u8;
typedef __s16 epass_s16;
typedef __s32 epass_s32;
typedef __u32 epass_u32;
typedef __u64 epass_u64;
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t epass_u8;
typedef int16_t epass_s16;
typedef int32_t epass_s32;
typedef uint32_t epass_u32;
typedef uint64_t epass_u64;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Bit-compatible with struct bpf_insn (regs: dst_reg and src_reg bitfields). */
struct epass_insn {
	epass_u8 code;
	epass_u8 regs;
	epass_s16 off;
	epass_s32 imm;
};

/* Log levels passed to epass_host.log. */
enum {
	EPASS_LOG_ERROR = 0,
	EPASS_LOG_WARN = 1,
	EPASS_LOG_INFO = 2,
	EPASS_LOG_DEBUG = 3,
};

/*
 * Platform services. alloc and free are required; the rest may be NULL.
 * alloc returns NULL on failure; size is never 0. should_yield is called
 * periodically from long loops (the kernel calls cond_resched() there) and
 * returns nonzero to abort the compilation with -EINTR.
 */
struct epass_host {
	void *ctx;
	void *(*alloc)(void *ctx, size_t size, size_t align);
	void (*free)(void *ctx, void *ptr, size_t size, size_t align);
	void (*log)(void *ctx, int level, const char *msg, size_t len);
	epass_u64 (*now_ns)(void *ctx);
	int (*should_yield)(void *ctx);
};

/* Return classes of helpers and kfuncs. */
enum {
	EPASS_RET_SCALAR = 0,
	EPASS_RET_MAP_VALUE_OR_NULL = 1,
	EPASS_RET_MEM_OR_NULL = 2,
	EPASS_RET_PTR = 3,
};

/* A call signature: arguments r1..r(nargs); r(optional_from+1).. may be unset. */
struct epass_sig {
	epass_u8 nargs;
	epass_u8 optional_from;
	epass_u8 ret;
	epass_u8 reserved;
};

/* Accept calls whose signature is unknown, assuming all five arguments are
 * live (userspace only: the kernel always knows its helpers). */
#define EPASS_FACTS_UNKNOWN_CALLS (1u << 0)

/*
 * What the platform knows about the program. NULL facts mean: ISA v4,
 * ePass's built-in helper table, unknown calls accepted.
 * helper/kfunc return 0 and fill *sig, or nonzero if unknown. A NULL helper
 * callback uses the built-in table; a NULL kfunc callback knows no kfuncs.
 */
struct epass_facts {
	void *ctx;
	epass_u32 prog_type;
	epass_u32 isa; /* highest accepted ISA level, 1..4 (0 = 4) */
	epass_u32 flags;
	int (*helper)(void *ctx, epass_s32 id, struct epass_sig *sig);
	int (*kfunc)(void *ctx, epass_s32 btf_id, epass_s16 fd_idx, struct epass_sig *sig);
};

enum {
	EPASS_PRESET_USER = 0,
	EPASS_PRESET_KERNEL = 1,
};

/*
 * Administrator policy, e.g. "mode=optin,user_popt=1,ir=0,+lower_throw,-const_prop".
 * A NULL policy is the permissive userspace default. Zero limits take the
 * preset's value.
 */
struct epass_policy {
	const char *str;
	epass_u32 len;
	epass_u32 preset;
	epass_u32 max_insns;
	epass_u32 log_bytes;
	epass_u64 max_bytes;
	epass_u64 time_ns;
};

/* The loader asked for ePass (matters under mode=optin). */
#define EPASS_IN_REQUESTED (1u << 0)

/*
 * One program: bytecode (insns, insn_cnt) or a binary IR blob (ir, ir_len),
 * never both. gopt is the global option string ("verbose=2,isa=v3"), popt
 * the pass option string ("const_prop,!zext_elim"); neither needs a NUL.
 */
struct epass_input {
	const struct epass_insn *insns;
	epass_u32 insn_cnt;
	epass_u32 ir_len;
	const void *ir;
	const char *gopt;
	const char *popt;
	epass_u32 gopt_len;
	epass_u32 popt_len;
	epass_u32 flags;
	epass_u32 reserved;
};

/*
 * Result. insns/offsets are set only when epass_compile returns 0.
 * offsets[i] is the output index of original instruction i (removed
 * instructions map to the next surviving one); offsets[insn_cnt_in] is the
 * output length. It is not monotonic in general, so a loader remapping
 * line_info must sort and deduplicate. offsets is NULL for IR input.
 * log is NUL-terminated (log_len excludes the NUL) or NULL.
 */
struct epass_output {
	struct epass_insn *insns;
	epass_u32 insn_cnt;
	epass_u32 offsets_cnt;
	epass_u32 *offsets;
	char *log;
	epass_u32 log_len;
	int error; /* the fail-open error when epass_compile returns 1 */
	const struct epass_host *host; /* private */
};

int epass_compile(const struct epass_host *host, const struct epass_facts *facts,
		  const struct epass_policy *policy, const struct epass_input *in,
		  struct epass_output *out);

/* Release out's buffers; safe on a zeroed or already freed output. */
void epass_output_free(struct epass_output *out);

#ifndef __KERNEL__
/* libepass.a only: a host over malloc/free that logs nothing. */
const struct epass_host *epass_default_host(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _EPASS_H */
