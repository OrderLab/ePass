#include <linux/bpf_ir.h>

#define MAX_RUN_INSN 1000

void add_counter(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block *entry = fun->entry;
	struct ir_insn *alloc_insn = bpf_ir_create_alloc_insn_bb(
		env, entry, IR_VR_TYPE_32, INSERT_FRONT);
	bpf_ir_create_store_insn(env, alloc_insn, alloc_insn,
				 bpf_ir_value_const32(0), INSERT_BACK);
	struct ir_basic_block **pos;

	struct ir_basic_block *err_bb = bpf_ir_create_bb(env, fun);
	bpf_ir_create_ret_insn_bb(env, err_bb, bpf_ir_value_const32(1),
				  INSERT_BACK);

	// Create an 8 bytes array to store the error message "exit"
	struct ir_insn *alloc_array = bpf_ir_create_allocarray_insn_bb(
		env, err_bb, IR_VR_TYPE_64, 1, INSERT_FRONT);

	struct ir_insn *straw1 = bpf_ir_create_storeraw_insn(
		env, alloc_array, IR_VR_TYPE_8,
		bpf_ir_addr_val(bpf_ir_value_insn(alloc_array), 0x4),
		bpf_ir_value_const32(0), INSERT_BACK);

	struct ir_insn *straw2 = bpf_ir_create_storeraw_insn(
		env, straw1, IR_VR_TYPE_32,
		bpf_ir_addr_val(bpf_ir_value_insn(alloc_array), 0),
		bpf_ir_value_const32(0x74697865), INSERT_BACK);

	struct ir_insn *elemptr = bpf_ir_create_getelemptr_insn(
		env, straw2, alloc_array, bpf_ir_value_const32(0), INSERT_BACK);

	struct ir_insn *call_insn =
		bpf_ir_create_call_insn(env, elemptr, 6,
					INSERT_BACK); // A printk call

	bpf_ir_phi_add_call_arg(env, call_insn, bpf_ir_value_insn(elemptr));

	bpf_ir_phi_add_call_arg(env, call_insn, bpf_ir_value_const32(5));

	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		if (bb->preds.num_elem <= 1) {
			// Skip Non-loop BBs
			continue;
		}
		size_t len = bpf_ir_bb_len(bb);
		struct ir_insn *last = bpf_ir_get_last_insn(bb);
		if (!last) {
			// No insn in the bb
			continue;
		}
		struct ir_insn *load_insn = bpf_ir_create_load_insn(
			env, last, bpf_ir_value_insn(alloc_insn), INSERT_FRONT);
		struct ir_insn *added = bpf_ir_create_bin_insn(
			env, load_insn, bpf_ir_value_insn(load_insn),
			bpf_ir_value_const32(len), IR_INSN_ADD, IR_ALU_64,
			INSERT_BACK);
		struct ir_insn *store_back = bpf_ir_create_store_insn(
			env, added, alloc_insn, bpf_ir_value_insn(added),
			INSERT_BACK);
		struct ir_basic_block *new_bb =
			bpf_ir_split_bb(env, fun, store_back, false);
		bpf_ir_create_jbin_insn(env, store_back,
					bpf_ir_value_insn(added),
					bpf_ir_value_const32(MAX_RUN_INSN),
					new_bb, err_bb, IR_INSN_JGT, IR_ALU_64,
					INSERT_BACK);
		// Manually connect BBs
		bpf_ir_connect_bb(env, bb, err_bb);
	}
}
