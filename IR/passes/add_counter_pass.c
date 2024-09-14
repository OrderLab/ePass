#include <linux/bpf_ir.h>

void add_counter(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block *entry = fun->entry;
	struct ir_insn *alloc_insn = bpf_ir_create_alloc_insn_bb(
		env, entry, IR_VR_TYPE_64, INSERT_FRONT);
	struct ir_value val;
	val.type = IR_VALUE_CONSTANT;
	val.data.constant_d = 0;
	val.const_type = IR_ALU_64;
	bpf_ir_create_store_insn(env, alloc_insn, alloc_insn, val, INSERT_BACK);
	struct ir_basic_block **pos;

	struct ir_basic_block *err_bb = bpf_ir_create_bb(env, fun);
	val.data.constant_d = 1;
	val.const_type = IR_ALU_32;
	bpf_ir_create_ret_insn_bb(env, err_bb, val, INSERT_BACK);

	// Create an 8 bytes array to store the error message "exit"
	struct ir_insn *insn;
	insn = bpf_ir_create_allocarray_insn_bb(env, err_bb, IR_VR_TYPE_64, 1,
						INSERT_FRONT);
	struct ir_insn *elemptr =
		bpf_ir_create_getelemptr_insn(env, insn, insn, 4, INSERT_BACK);

	insn = bpf_ir_create_call_insn(env, elemptr, 6,
				       INSERT_BACK); // A printk call

	bpf_ir_phi_add_call_arg(env, insn, bpf_ir_value_insn(elemptr));
	val.type = IR_VALUE_CONSTANT;
	val.data.constant_d = 5;

	bpf_ir_phi_add_call_arg(env, insn, val);

	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		// if (bb->preds.num_elem <= 1) {
		// 	// Skip Non-loop BBs
		// 	continue;
		// }
		size_t len = bpf_ir_bb_len(bb);
		struct ir_insn *last = bpf_ir_get_last_insn(bb);
		if (!last) {
			// No insn in the bb
			continue;
		}
		struct ir_insn *load_insn = bpf_ir_create_load_insn(
			env, last, bpf_ir_value_insn(alloc_insn), INSERT_FRONT);
		struct ir_value val1;
		val1.type = IR_VALUE_CONSTANT;
		val1.data.constant_d = len;
		val1.const_type = IR_ALU_32;
		struct ir_value val2;
		val2.type = IR_VALUE_INSN;
		val2.data.insn_d = load_insn;
		struct ir_insn *added = bpf_ir_create_bin_insn(
			env, load_insn, val1, val2, IR_INSN_ADD, IR_ALU_64,
			INSERT_BACK);
		val.data.insn_d = added;
		val.type = IR_VALUE_INSN;
		struct ir_insn *store_back = bpf_ir_create_store_insn(
			env, added, alloc_insn, val, INSERT_BACK);
		struct ir_basic_block *new_bb =
			bpf_ir_split_bb(env, fun, store_back);
		val2.data.insn_d = added;
		val1.data.constant_d = 0x10000;
		bpf_ir_create_jbin_insn(env, store_back, val2, val1, new_bb,
					err_bb, IR_INSN_JGT, IR_ALU_64,
					INSERT_BACK);
		// Manually connect BBs
		bpf_ir_connect_bb(env, bb, err_bb);
	}
}
