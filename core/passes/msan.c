// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

void msan(struct bpf_ir_env *env, struct ir_function *fun, void *param)
{
	// Add the 64B mapping space
	struct ir_insn *arr = bpf_ir_create_allocarray_insn_bb(
		env, fun->entry, IR_VR_TYPE_64, 8, INSERT_FRONT_AFTER_PHI);
	for (int i = 0; i < 8; ++i) {
		bpf_ir_create_storeraw_insn(
			env, arr, IR_VR_TYPE_64,
			bpf_ir_addr_val(bpf_ir_value_insn(arr), i * 8),
			bpf_ir_value_const32(0), INSERT_BACK);
	}
}

const struct builtin_pass_cfg bpf_ir_kern_msan =
	DEF_BUILTIN_PASS_CFG("msan", NULL, NULL);
