// SPDX-License-Identifier: GPL-2.0-only
#include "ir.h"
#include "linux/bpf_ir.h"

void translate_malloc(struct bpf_ir_env *env, struct ir_function *fun)
{
}

/**
 * bpf_ir_handle_ecalls - Handle ecall instructions in the IR
 *
 * This pass translates ecall instructions into appropriate IR instructions
 * according to the semantics defined for ecall operations.
 */

void bpf_ir_handle_ecalls(struct bpf_ir_env *env, struct ir_function *fun,
			  void *param)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_ECALL) {
				bpf_ir_erase_insn(env, insn);
			}
		}
	}
}
