// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

// JMP Complexity

void bpf_ir_jmp_complexity(struct bpf_ir_env *env, struct ir_function *fun,
			   void *param)
{
	struct array jmp_insns;
	INIT_ARRAY(&jmp_insns, struct ir_insn *);
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (bpf_ir_is_jmp(insn)) {
				bpf_ir_array_push(env, &jmp_insns, &insn);
			}
		}
	}
	if (jmp_insns.num_elem == 0) {
		return;
	}
	struct ir_basic_block *entry = fun->entry;
	struct ir_insn *alloc_insn = bpf_ir_create_alloc_insn_bb(
		env, entry, IR_VR_TYPE_32, INSERT_FRONT);
	bpf_ir_create_store_insn(env, alloc_insn, alloc_insn,
				 bpf_ir_value_const32(0), INSERT_BACK);
	struct ir_insn **pos2;
	array_for(pos2, jmp_insns)
	{
		struct ir_insn *insn = *pos2;
		struct ir_insn *load_insn = bpf_ir_create_load_insn(
			env, insn, bpf_ir_value_insn(alloc_insn), INSERT_FRONT);
		struct ir_insn *added = bpf_ir_create_bin_insn(
			env, load_insn, bpf_ir_value_insn(load_insn),
			bpf_ir_value_const32(1), IR_INSN_ADD, IR_ALU_64,
			INSERT_BACK);
		struct ir_insn *store_back = bpf_ir_create_store_insn(
			env, added, alloc_insn, bpf_ir_value_insn(added),
			INSERT_BACK);
		struct ir_basic_block *new_bb, *err_bb;
		bpf_ir_bb_create_error_block(env, fun, store_back, INSERT_BACK,
					     &err_bb, &new_bb);
		bpf_ir_create_jbin_insn(env, store_back,
					bpf_ir_value_insn(added),
					bpf_ir_value_const32(100), new_bb,
					err_bb, IR_INSN_JGT, IR_ALU_64,
					INSERT_BACK);
	}
	bpf_ir_array_free(&jmp_insns);
}