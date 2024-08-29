#include <linux/bpf_ir.h>

__u8 bpf_ir_value_equal(struct ir_value a, struct ir_value b)
{
	if (a.type != b.type) {
		return 0;
	}
	if (a.type == IR_VALUE_CONSTANT) {
		return a.data.constant_d == b.data.constant_d;
	}
	if (a.type == IR_VALUE_INSN) {
		return a.data.insn_d == b.data.insn_d;
	}
	if (a.type == IR_VALUE_STACK_PTR) {
		return 1;
	}
	CRITICAL("Error");
}

struct ir_value bpf_ir_value_insn(struct ir_insn *insn)
{
	return (struct ir_value){ .type = IR_VALUE_INSN, .data.insn_d = insn };
}

struct ir_value bpf_ir_value_stack_ptr(void)
{
	return (struct ir_value){ .type = IR_VALUE_STACK_PTR };
}
