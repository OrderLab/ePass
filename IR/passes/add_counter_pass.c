#include "bpf_ir.h"

void add_counter(struct ir_function *fun)
{
	struct ir_basic_block *entry = fun->entry;
	struct ir_insn *alloc_insn =
		create_alloc_insn_bb(entry, IR_VR_TYPE_64, INSERT_FRONT);
	struct ir_value val;
	val.type = IR_VALUE_CONSTANT;
	val.data.constant_d = 0;
	create_store_insn(alloc_insn, alloc_insn, val, INSERT_BACK);
	struct ir_basic_block **pos;

	struct ir_basic_block *err_bb = create_bb(fun);
	val.data.constant_d = 1;
	create_ret_insn_bb(err_bb, val, INSERT_BACK);

	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		size_t len = bb_len(bb);
		struct ir_insn *last = get_last_insn(bb);
		if (!last) {
			// No insn in the bb
			continue;
		}
		struct ir_insn *load_insn = create_load_insn(
			last, bpf_ir_value_insn(alloc_insn), INSERT_FRONT);
		struct ir_value val1;
		val1.type = IR_VALUE_CONSTANT;
		val1.data.constant_d = len;
		struct ir_value val2;
		val2.type = IR_VALUE_INSN;
		val2.data.insn_d = load_insn;
		struct ir_insn *added = create_bin_insn(load_insn, val1, val2,
							IR_INSN_ADD, IR_ALU_64,
							INSERT_BACK);
		val.data.insn_d = added;
		val.type = IR_VALUE_INSN;
		struct ir_insn *store_back =
			create_store_insn(added, alloc_insn, val, INSERT_BACK);
		struct ir_basic_block *new_bb = split_bb(fun, store_back);
		val2.data.insn_d = added;
		val1.data.constant_d = 0x10000;
		create_jbin_insn(store_back, val1, val2, new_bb, err_bb,
				 IR_INSN_JLT, IR_ALU_64, INSERT_BACK);
		// Manually connect BBs
		connect_bb(bb, err_bb);
	}
}
