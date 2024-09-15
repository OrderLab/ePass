#include <linux/bpf_ir.h>

bool bpf_ir_value_equal(struct ir_value a, struct ir_value b)
{
	if (a.type != b.type) {
		return false;
	}
	if (a.type == IR_VALUE_CONSTANT) {
		return a.data.constant_d == b.data.constant_d;
	}
	if (a.type == IR_VALUE_INSN) {
		return a.data.insn_d == b.data.insn_d;
	}
	CRITICAL("Error");
}

struct ir_value bpf_ir_value_insn(struct ir_insn *insn)
{
	return (struct ir_value){ .type = IR_VALUE_INSN, .data.insn_d = insn };
}

struct ir_value bpf_ir_value_const32(s32 val)
{
	return (struct ir_value){ .type = IR_VALUE_CONSTANT,
				  .data.constant_d = val,
				  .const_type = IR_ALU_32 };
}

struct ir_value bpf_ir_value_const64(s64 val)
{
	return (struct ir_value){ .type = IR_VALUE_CONSTANT,
				  .data.constant_d = val,
				  .const_type = IR_ALU_64 };
}

struct ir_address_value bpf_ir_addr_val(struct ir_value value, s16 offset)
{
	return (struct ir_address_value){ .value = value, .offset = offset };
}

struct ir_value bpf_ir_value_stack_ptr(struct ir_function *fun)
{
	return bpf_ir_value_insn(fun->sp);
}
