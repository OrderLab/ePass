// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

void msan(struct bpf_ir_env *env, struct ir_function *fun, void *param)
{
	// Add the 64B mapping space
	bpf_ir_create_allocarray_insn_bb(env, fun->entry, IR_VR_TYPE_64, 64,
					 INSERT_FRONT_AFTER_PHI);
}
