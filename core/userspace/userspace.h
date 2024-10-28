// SPDX-License-Identifier: GPL-2.0-only
#ifndef _USP_TEST_H_
#define _USP_TEST_H_

#include <linux/bpf_ir.h>

void masking_pass(struct bpf_ir_env *env, struct ir_function *fun, void *param);

void test_pass1(struct bpf_ir_env *env, struct ir_function *fun, void *param);

#endif
