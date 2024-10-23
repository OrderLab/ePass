// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

static u32 en_pred_num(struct ir_function *fun, struct ir_basic_block *bb)
{
	if (fun->entry == bb) {
		return bb->preds.num_elem + 1;
	} else {
		return bb->preds.num_elem;
	}
}

void add_counter(struct bpf_ir_env *env, struct ir_function *fun, void *param)
{
	int max_run_insn = 1000000;
	if (param) {
		max_run_insn = *(int *)param;
	}
	struct ir_basic_block *entry = fun->entry;
	struct ir_insn *alloc_insn = bpf_ir_create_alloc_insn_bb(
		env, entry, IR_VR_TYPE_32, INSERT_FRONT);
	bpf_ir_create_store_insn(env, alloc_insn, alloc_insn,
				 bpf_ir_value_const32(0), INSERT_BACK);
	struct ir_basic_block **pos;

	struct array critical_bbs;
	INIT_ARRAY(&critical_bbs, struct ir_basic_block *);

	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		if (en_pred_num(fun, bb) > 1) {
			struct ir_basic_block **pos2;
			array_for(pos2, bb->preds)
			{
				struct ir_basic_block *pred = *pos2;
				if (pred->flag & IR_BB_HAS_COUNTER) {
					continue;
				}
				pred->flag |= IR_BB_HAS_COUNTER;
				bpf_ir_array_push(env, &critical_bbs, &pred);
			}
		}
	}

	array_for(pos, critical_bbs)
	{
		struct ir_basic_block *bb = *pos;
		// size_t len = bpf_ir_bb_len(bb);
		struct ir_insn *last = bpf_ir_get_last_insn(bb);
		if (!last || !bpf_ir_is_jmp(last)) {
			// Directly insert at the end of the BB
			DBGASSERT(bb->succs.num_elem == 1);
			struct ir_insn *load_insn = bpf_ir_create_load_insn_bb(
				env, bb, bpf_ir_value_insn(alloc_insn),
				INSERT_BACK);
			struct ir_value cv = bpf_ir_value_const32(-1);
			cv.builtin_const = IR_BUILTIN_BB_INSN_CRITICAL_CNT;
			struct ir_insn *added = bpf_ir_create_bin_insn(
				env, load_insn, bpf_ir_value_insn(load_insn),
				cv, IR_INSN_ADD, IR_ALU_64, INSERT_BACK);
			struct ir_insn *store_back = bpf_ir_create_store_insn(
				env, added, alloc_insn,
				bpf_ir_value_insn(added), INSERT_BACK);
			struct ir_basic_block **succ =
				bpf_ir_array_get_void(&bb->succs, 0);
			struct ir_basic_block *err_bb =
				bpf_ir_create_bb(env, fun);
			bpf_ir_create_throw_insn_bb(env, err_bb, INSERT_BACK);
			bpf_ir_create_jbin_insn(
				env, store_back, bpf_ir_value_insn(added),
				bpf_ir_value_const32(max_run_insn), *succ,
				err_bb, IR_INSN_JGT, IR_ALU_64, INSERT_BACK);
			bpf_ir_connect_bb(env, bb, err_bb);
			continue;
		}
		struct ir_insn *load_insn = bpf_ir_create_load_insn(
			env, last, bpf_ir_value_insn(alloc_insn), INSERT_FRONT);
		struct ir_value cv = bpf_ir_value_const32(-1);
		cv.builtin_const = IR_BUILTIN_BB_INSN_CRITICAL_CNT;
		struct ir_insn *added = bpf_ir_create_bin_insn(
			env, load_insn, bpf_ir_value_insn(load_insn), cv,
			IR_INSN_ADD, IR_ALU_64, INSERT_BACK);
		struct ir_insn *store_back = bpf_ir_create_store_insn(
			env, added, alloc_insn, bpf_ir_value_insn(added),
			INSERT_BACK);
		struct ir_basic_block *new_bb =
			bpf_ir_split_bb(env, fun, store_back, false);
		struct ir_basic_block *err_bb = bpf_ir_create_bb(env, fun);
		bpf_ir_create_throw_insn_bb(env, err_bb, INSERT_BACK);
		bpf_ir_create_jbin_insn(env, store_back,
					bpf_ir_value_insn(added),
					bpf_ir_value_const32(max_run_insn),
					new_bb, err_bb, IR_INSN_JGT, IR_ALU_64,
					INSERT_BACK);
		// Manually connect BBs
		bpf_ir_connect_bb(env, bb, err_bb);
	}

	bpf_ir_array_free(&critical_bbs);
}
