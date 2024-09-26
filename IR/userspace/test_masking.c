#include <linux/bpf_ir.h>

#define CHECK_COND(cond) \
	if (!(cond)) {   \
		return;  \
	}

void masking_pass(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_insn *insn = NULL;
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *linsn;
		list_for_each_entry(linsn, &bb->ir_insn_head, list_ptr) {
			if (linsn->op == IR_INSN_LOADRAW) {
				insn = linsn;
				break;
			}
		}
	}
	CHECK_COND(insn);
	// Found the IR instruction
	CHECK_COND(insn->op == IR_INSN_LOADRAW)
	// LOADRAW src
	struct ir_value v = insn->addr_val.value;

	// struct ir_raw_pos v1p = v.raw_pos;
	CHECK_COND(v.type == IR_VALUE_INSN);
	struct ir_insn *aluinsn = v.data.insn_d;
	CHECK_COND(bpf_ir_is_alu(aluinsn));
	struct ir_value index;
	CHECK_COND(aluinsn->values[0].type == IR_VALUE_INSN &&
		   aluinsn->values[1].type == IR_VALUE_INSN);

	if (aluinsn->values[0].data.insn_d->op == IR_INSN_LOADIMM_EXTRA) {
		index = aluinsn->values[1];
	} else if (aluinsn->values[1].data.insn_d->op ==
		   IR_INSN_LOADIMM_EXTRA) {
		index = aluinsn->values[0];
	} else {
		return;
	}

	struct ir_basic_block *err_bb = bpf_ir_create_bb(env, fun);
	bpf_ir_create_ret_insn_bb(env, err_bb, bpf_ir_value_const32(1),
				  INSERT_BACK);
	struct ir_basic_block *old_bb = aluinsn->parent_bb;
	// Split before insn
	struct ir_basic_block *new_bb =
		bpf_ir_split_bb(env, fun, aluinsn, true);

	bpf_ir_create_jbin_insn_bb(env, old_bb, index,
				   bpf_ir_value_const32(100), new_bb, err_bb,
				   IR_INSN_JSLT, IR_ALU_64, INSERT_BACK);

	struct ir_basic_block *new_bb2 =
		bpf_ir_split_bb(env, fun, aluinsn, true);

	bpf_ir_create_jbin_insn_bb(env, new_bb, index,
				   bpf_ir_value_const32(200), new_bb2, err_bb,
				   IR_INSN_JSGT, IR_ALU_64, INSERT_BACK);

	bpf_ir_connect_bb(env, old_bb, err_bb);
	bpf_ir_connect_bb(env, new_bb, err_bb);
}
