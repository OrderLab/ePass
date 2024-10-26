// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

static void remove_no_user_insn(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Remove all instructions that have no users, except for void instructions & calls

	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (bpf_ir_is_void(insn) || insn->op == IR_INSN_CALL) {
				continue;
			}
			if (insn->users.num_elem == 0) {
				bpf_ir_erase_insn(env, insn);
				CHECK_ERR();
			}
		}
	}
}

static void remove_unused_alloc(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Remove all alloc instructions that have no users
	struct array alloc_insns;
	INIT_ARRAY(&alloc_insns, struct ir_insn *);

	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (insn->op == IR_INSN_ALLOC) {
				bpf_ir_array_push(env, &alloc_insns, &insn);
			}
		}
	}

	struct ir_insn **pos2;
	array_for(pos2, alloc_insns)
	{
		bool has_load = false;
		struct ir_insn *insn = *pos2;
		struct ir_insn **pos3;
		array_for(pos3, insn->users)
		{
			struct ir_insn *user = *pos3;
			if (user->op == IR_INSN_LOAD) {
				has_load = true;
				break;
			}
		}
		if (!has_load) {
			// Remove all its store
			array_for(pos3, insn->users)
			{
				struct ir_insn *user = *pos3;
				bpf_ir_erase_insn(env, user);
				CHECK_ERR();
			}
			// Remove itself
			bpf_ir_erase_insn(env, insn);
			CHECK_ERR();
		}
	}

	bpf_ir_array_free(&alloc_insns);
}

void bpf_ir_optimize_ir(struct bpf_ir_env *env, struct ir_function *fun,
			void *param)
{
	remove_no_user_insn(env, fun);
	CHECK_ERR();

	remove_unused_alloc(env, fun);
	CHECK_ERR();
}
