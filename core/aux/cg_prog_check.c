// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>
#include "ir_cg.h"

static void check_userdata(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (!insn_cg_v2(insn)) {
				print_ir_insn_err(env, insn, "No userdata");
				RAISE_ERROR("No userdata");
			}
		}
	}
}

void bpf_ir_cg_prog_check(struct bpf_ir_env *env, struct ir_function *fun)
{
	tag_ir(fun);
	check_userdata(env, fun);
	CHECK_ERR();
}
