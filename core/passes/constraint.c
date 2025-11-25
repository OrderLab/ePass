// SPDX-License-Identifier: GPL-2.0-only
#include "ir.h"

/*
Adding constraint given by the verifier.
There are several types of constraints to check (side effects of the whole program):
1. Helper function/kfunc call argument
2. Helper function/kfunc return value
3. Program return code
*/

void bpf_ir_add_constraints(struct bpf_ir_env *env, struct ir_function *fun,
			    void *param)
{
	// struct verifier_constraint *constraints;

	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_CALL) {
				// function call argument & return value constraints
			}
			if (insn->op == IR_INSN_RET) {
				// program return value constraints
			}
		}
	}
}

const struct builtin_pass_cfg bpf_ir_add_constraints_pass =
	DEF_BUILTIN_PASS_CFG("add_constraints", NULL, NULL);