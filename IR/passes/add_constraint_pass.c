#include <linux/bpf_ir.h>

// Initialize some testing constraints
void init_test_constraints(struct ir_function *fun)
{
	INIT_ARRAY(&fun->value_constraints, struct ir_constraint);
}

void add_constraint(struct bpf_ir_env *env, struct ir_function *fun)
{
	init_test_constraints(fun); // For testing purpose

	struct ir_basic_block *err_bb = bpf_ir_create_bb(env, fun);
	struct ir_value val;
	val.type = IR_VALUE_CONSTANT;
	val.data.constant_d = 1;
	bpf_ir_create_ret_insn_bb(env, err_bb, val, INSERT_BACK);

	struct ir_constraint *pos;
	array_for(pos, fun->value_constraints)
	{
		struct ir_constraint c = *pos;
		if (c.type == CONSTRAINT_TYPE_VALUE_EQUAL) {
			struct ir_basic_block *newbb =
				bpf_ir_split_bb(env, fun, c.pos, false);
			bpf_ir_create_jbin_insn(env, c.pos, c.val, c.cval,
						newbb, err_bb, IR_INSN_JNE,
						IR_ALU_64, INSERT_FRONT);
			bpf_ir_connect_bb(env, c.pos->parent_bb, err_bb);
		} else if (c.type == CONSTRAINT_TYPE_VALUE_RANGE) {
			struct ir_basic_block *newbb =
				bpf_ir_split_bb(env, fun, c.pos, false);
			bpf_ir_create_jbin_insn(env, c.pos, c.val, c.start,
						newbb, err_bb, IR_INSN_JLT,
						IR_ALU_64, INSERT_FRONT);
			bpf_ir_connect_bb(env, c.pos->parent_bb, err_bb);
			struct ir_basic_block *newbb2 =
				bpf_ir_split_bb(env, fun, c.pos, false);
			bpf_ir_create_jbin_insn(env, c.pos, c.val, c.end,
						newbb2, err_bb, IR_INSN_JGE,
						IR_ALU_64, INSERT_FRONT);
			bpf_ir_connect_bb(env, c.pos->parent_bb, err_bb);
		} else {
			CRITICAL("Error");
		}
	}
}
