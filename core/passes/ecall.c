// SPDX-License-Identifier: GPL-2.0-only
#include "ir.h"

/**
 * bpf_ir_handle_ecalls - Handle ecall instructions in the IR
 *
 * This pass translates ecall instructions into appropriate IR instructions
 * according to the semantics defined for ecall operations.
 */

void bpf_ir_handle_ecalls(struct bpf_ir_env *env, struct ir_function *fun,
			  void *param)
{
}
