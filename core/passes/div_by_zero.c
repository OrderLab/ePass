// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

void bpf_ir_div_by_zero(struct bpf_ir_env *env, struct ir_function *fun,
			void *param)
{
	struct array div_insns;
	INIT_ARRAY(&div_insns, struct ir_insn *);
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_DIV) {
				bpf_ir_array_push(env, &div_insns, &insn);
			}
		}
	}
	struct ir_insn **pos2;
	array_for(pos2, div_insns)
	{
		struct ir_insn *insn = *pos2;
		if (insn->values[1].type == IR_VALUE_INSN) {
			// Check if it is equal to zero
			struct ir_insn *prev = bpf_ir_prev_insn(insn);
			struct ir_basic_block *bb = insn->parent_bb;
			if (!prev) {
				continue;
			}

			struct ir_basic_block *new_bb =
				bpf_ir_split_bb(env, fun, prev, INSERT_BACK);
			struct ir_basic_block *err_bb =
				bpf_ir_create_bb(env, fun);
			bpf_ir_create_throw_insn_bb(env, err_bb, INSERT_BACK);
			bpf_ir_create_jbin_insn(env, prev, insn->values[1],
						bpf_ir_value_const32(0), new_bb,
						err_bb, IR_INSN_JEQ, IR_ALU_64,
						INSERT_BACK);
			// Manually connect BBs
			bpf_ir_connect_bb(env, bb, err_bb);
		}
	}
	bpf_ir_array_free(&div_insns);
}

const struct builtin_pass_cfg bpf_ir_kern_div_by_zero_pass =
	DEF_BUILTIN_PASS_ENABLE_CFG("div_by_zero", NULL, NULL);
