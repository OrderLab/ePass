// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

// An optimization mentioned in MERLIN that is hard to do in LLVM

void bpf_ir_optimize_code_compaction(struct bpf_ir_env *env,
				     struct ir_function *fun, void *param)
{
	struct array opt_insns;
	INIT_ARRAY(&opt_insns, struct ir_insn *);
	struct ir_basic_block **pos;
	struct ir_insn *prev_insn = NULL;
	struct ir_insn *cur_insn = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		list_for_each_entry(cur_insn, &bb->ir_insn_head, list_ptr) {
			if (!prev_insn) {
				prev_insn = cur_insn;
			}
			if (prev_insn->op == IR_INSN_LSH &&
			    cur_insn->op == IR_INSN_RSH) {
				if (prev_insn->values[1].type !=
					    IR_VALUE_CONSTANT ||
				    cur_insn->values[1].type !=
					    IR_VALUE_CONSTANT) {
					continue;
				}
				if (prev_insn->values[0].type ==
					    IR_VALUE_INSN &&
				    cur_insn->values[0].type == IR_VALUE_INSN &&
				    prev_insn->values[0].data.insn_d ==
					    cur_insn->values[0].data.insn_d) {
					// Same!
					bpf_ir_array_push(env, &opt_insns,
							  &cur_insn);
					bpf_ir_array_push(env, &opt_insns,
							  &prev_insn);
				}
			}
			prev_insn = cur_insn;
		}
	}
	if (opt_insns.num_elem == 0) {
		return;
	}
	struct ir_insn **pos2;
	array_for(pos2, opt_insns)
	{
		struct ir_insn *insn = *pos2;
		if (insn->op == IR_INSN_RSH) {
			// Insert optimized code
			struct ir_insn *ni = bpf_ir_create_assign_insn(
				env, insn, insn->values[0], INSERT_BACK);
			ni->vr_type = IR_VR_TYPE_32;
		}
		bpf_ir_erase_insn(env, insn);
	}
	bpf_ir_array_free(&opt_insns);
}