// SPDX-License-Identifier: GPL-2.0-only
#ifndef _EPASS_TOOL_H_
#define _EPASS_TOOL_H_

#include <linux/bpf_ir.h>

struct user_opts {
	char gopt[64];
	char popt[64];
	char prog[64];
	char sec[64];
	struct bpf_ir_opts opts;
	bool no_compile;
	bool auto_sec;
	bool log;

	enum {
		MODE_READ,
		MODE_READLOAD,
		MODE_PRINT,
	} mode;
};

void masking_pass(struct bpf_ir_env *env, struct ir_function *fun, void *param);

void test_pass1(struct bpf_ir_env *env, struct ir_function *fun, void *param);

int printlog(struct user_opts uopts);

int print(struct user_opts uopts);

int read(struct user_opts uopts);

int readload(struct user_opts uopts);

int readlog(struct user_opts uopts);

void enable_builtin(struct bpf_ir_env *env);

extern struct bpf_ir_opts common_opts;

// Passes

extern const struct builtin_pass_cfg bpf_ir_kern_insn_counter_pass;
extern const struct builtin_pass_cfg bpf_ir_kern_optimization_pass;
extern const struct builtin_pass_cfg bpf_ir_kern_msan;
extern const struct builtin_pass_cfg bpf_ir_kern_div_by_zero_pass;
extern const struct builtin_pass_cfg bpf_ir_kern_compaction_pass;

#endif
