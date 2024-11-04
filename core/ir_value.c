// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

bool bpf_ir_const_equal(struct ir_constant a, struct ir_constant b)
{
	if (a.const_type != b.const_type) {
		return false;
	}
	if (a.num != b.num) {
		return false;
	}
	if (a.pp != b.pp) {
		return false;
	}
	return true;
}

bool bpf_ir_value_equal(struct ir_value a, struct ir_value b)
{
	if (a.type != b.type) {
		return false;
	}
	if (a.type == IR_VALUE_CONSTANT) {
		return bpf_ir_const_equal(a.data.constant_d, b.data.constant_d);
	}
	if (a.type == IR_VALUE_INSN) {
		return a.data.insn_d == b.data.insn_d;
	}
	CRITICAL("Error");
}

static struct ir_value value_base(void)
{
	// Create a new value
	return (struct ir_value){ .type = IR_VALUE_UNDEF,
				  .raw_pos = { .valid = false } };
}

struct ir_value bpf_ir_value_insn(struct ir_insn *insn)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_INSN;
	v.data.insn_d = insn;
	return v;
}

struct ir_value bpf_ir_value_undef(void)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_UNDEF;
	return v;
}

struct ir_constant bpf_ir_const32(s32 val){
	return (struct ir_constant){
		.const_type = IR_ALU_32,
		.num = val,
		.pp = NULL,
	};
}

struct ir_constant bpf_ir_const64(s64 val){
	return (struct ir_constant){
		.const_type = IR_ALU_64,
		.num = val,
		.pp = NULL,
	};
}

struct ir_value bpf_ir_value_const32(s32 val)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_CONSTANT;
	v.data.constant_d = bpf_ir_const32(val);
	return v;
}

struct ir_value bpf_ir_value_const64(s64 val)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_CONSTANT;
	v.data.constant_d = bpf_ir_const64(val);
	return v;
}

struct ir_value bpf_ir_value_const32_rawoff(s32 val)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_CONSTANT;
	v.data.constant_d = (struct ir_constant){
		.const_type = IR_ALU_32,
		.num = val,
		.pp = bpf_ir_insnpp_rawoff,
	};
	return v;
}

struct ir_value bpf_ir_value_const64_rawoff(s64 val)
{
	struct ir_value v = value_base();
	v.type = IR_VALUE_CONSTANT;
	v.data.constant_d = (struct ir_constant){
		.const_type = IR_ALU_64,
		.num = val,
		.pp = bpf_ir_insnpp_rawoff,
	};
	return v;
}

struct ir_address_value bpf_ir_addr_val(struct ir_value value, s16 offset)
{
	return (struct ir_address_value){ .value = value,
					  .offset = offset };
}

struct ir_value bpf_ir_value_stack_ptr(struct ir_function *fun)
{
	return bpf_ir_value_insn(fun->sp);
}

void bpf_ir_change_value(struct bpf_ir_env *env, struct ir_insn *insn,
			 struct ir_value *old, struct ir_value new)
{
	bpf_ir_val_remove_user(*old, insn);
	*old = new;
	bpf_ir_val_add_user(env, new, insn);
}
