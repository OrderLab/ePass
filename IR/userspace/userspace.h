#ifndef _USP_TEST_H_
#define _USP_TEST_H_

#include <linux/bpf_ir.h>

void masking_pass(struct bpf_ir_env *env, struct ir_function *fun);

#endif
