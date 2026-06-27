/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ePass C ABI.
 *
 * Minimal C interface to the userspace ePass eBPF compiler (Rust `epass-ir`).
 * Link against `libepass_ir.a` (or `.so`).
 *
 * Typical use (e.g. from libbpf):
 *
 *     int err;
 *     epass_result *r = epass_run(insns, insn_cnt, getenv("LIBBPF_EPASS_GOPT"), &err);
 *     if (!r) { handle error code `err`; }
 *     else {
 *         const struct bpf_insn *out = (const void *)epass_result_insns(r);
 *         size_t out_cnt = epass_result_insn_cnt(r);
 *         bpf_program__set_insns(prog, out, out_cnt);
 *         epass_result_free(r);
 *     }
 */
#ifndef _EPASS_H
#define _EPASS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * An eBPF instruction, bit-compatible with the kernel/libbpf `struct bpf_insn`.
 * `regs` packs dst_reg (low nibble) and src_reg (high nibble).
 */
struct epass_insn {
	uint8_t code;
	uint8_t regs;
	int16_t off;
	int32_t imm;
};

/* Opaque result handle. */
typedef struct epass_result epass_result;

/*
 * Run the ePass pipeline (lift -> passes -> codegen) on a program.
 *
 * `insns`    : pointer to `insn_cnt` instructions (struct bpf_insn or epass_insn;
 *              the layouts are identical).
 * `gopt`     : NUL-terminated global-option string (comma-separated), or NULL.
 *              Recognized keys: verbose=<n>, disable_coalesce, no_prog_check,
 *              print_bpf, print_dump, print_detail, printonly, dotgraph.
 * `out_err`  : if non-NULL, receives 0 on success or a negative errno on failure.
 *
 * Returns a result handle on success, or NULL on failure.
 */
epass_result *epass_run(const struct epass_insn *insns, size_t insn_cnt,
			const char *gopt, int *out_err);

/* Pointer to the rewritten instruction array (valid until epass_result_free). */
const struct epass_insn *epass_result_insns(const epass_result *r);

/* Number of rewritten instructions. */
size_t epass_result_insn_cnt(const epass_result *r);

/* NUL-terminated log text from the run (valid until epass_result_free). */
const char *epass_result_log(const epass_result *r);

/* Free a result handle returned by epass_run(). */
void epass_result_free(epass_result *r);

#ifdef __cplusplus
}
#endif

#endif /* _EPASS_H */
