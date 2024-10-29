// SPDX-License-Identifier: GPL-2.0-only
#ifndef _USP_TEST_H_
#define _USP_TEST_H_

#include <linux/bpf_ir.h>

struct user_opts {
	char gopt[64];
	char popt[64];
	char prog[64];
	char sec[64];
	struct bpf_ir_opts opts;
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

#endif
