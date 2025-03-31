// SPDX-License-Identifier: GPL-2.0-only
#ifndef _EPASS_TOOL_H_
#define _EPASS_TOOL_H_

#include <linux/bpf_ir.h>

struct user_opts {
	char gopt[64];
	char popt[64];
	char prog[64];
	char prog_out[64];
	enum { OUTPUT_SEC_ONLY, OUTPUT_LOG } output_format;

	char sec[64];
	struct bpf_ir_opts opts;
	bool no_compile;

	// Automatically detect section.
	bool auto_sec;

	// Load the modified object to kernel.
	bool load;

	// Do not run ePass transformations before loading to kernel.
	// Will override `load` to true.
	bool direct_load;

	enum {
		MODE_READ,
		MODE_PRINT,
	} mode;
};

void masking_pass(struct bpf_ir_env *env, struct ir_function *fun, void *param);

int epass_printlog(struct user_opts uopts);

int epass_print(struct user_opts uopts);

int epass_read(struct user_opts uopts);

int epass_run(struct user_opts uopts, const struct bpf_insn *insn, size_t sz);

int epass_readload(struct user_opts uopts);

int epass_readlog(struct user_opts uopts);

void enable_builtin(struct bpf_ir_env *env);

extern struct bpf_ir_opts common_opts;

// Passes

void test_pass1(struct bpf_ir_env *env, struct ir_function *fun, void *param);

extern const struct builtin_pass_cfg bpf_ir_kern_insn_counter_pass;
extern const struct builtin_pass_cfg bpf_ir_kern_optimization_pass;
extern const struct builtin_pass_cfg bpf_ir_kern_msan;
extern const struct builtin_pass_cfg bpf_ir_kern_div_by_zero_pass;
extern const struct builtin_pass_cfg bpf_ir_kern_compaction_pass;

#endif
