// SPDX-License-Identifier: GPL-2.0-only
#include "ir.h"

// Testing spill registers
void test_pass1(struct bpf_ir_env *env, struct ir_function *fun, void *param)
{
	struct ir_basic_block *bb = fun->entry;
	struct ir_insn *insns[10];
	for (int i = 0; i < 10; ++i) {
		insns[i] = bpf_ir_create_bin_insn_bb(env, bb,
						     bpf_ir_value_const32(i),
						     bpf_ir_value_const32(1),
						     IR_INSN_ADD, IR_ALU_64,
						     INSERT_FRONT);
	}
	struct ir_insn *call =
		bpf_ir_create_call_insn(env, insns[0], 5, INSERT_BACK);
	for (int i = 0; i < 10; ++i) {
		bpf_ir_create_bin_insn(env, call, bpf_ir_value_insn(insns[i]),
				       bpf_ir_value_const32(1), IR_INSN_ADD,
				       IR_ALU_64, INSERT_BACK);
	}
}
