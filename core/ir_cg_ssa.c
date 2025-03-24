// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>
#include "ir_cg.h"

/*

Using SSA-based RA and graph coloring algorithm.

Algorithms are based on the following paper:

Pereira, F., and Palsberg, J., "Register Allocation via the Coloring of Chordal Graphs", APLAS, pp 315-329 (2005)

*/

static void ir_init_insn_cg(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_insn_cg_extra_v2 *extra = NULL;
	SAFE_MALLOC(extra, sizeof(struct ir_insn_cg_extra_v2));
	insn->user_data = extra;

	extra->dst = bpf_ir_is_void(insn) ? NULL : insn;
	extra->vr_pos.allocated = false;
	extra->vr_pos.spilled = 0;
	extra->vr_pos.spilled_size = 0;
	extra->vr_pos.alloc_reg = 0;

	INIT_PTRSET_DEF(&extra->adj);

	INIT_PTRSET_DEF(&extra->in);
	INIT_PTRSET_DEF(&extra->out);
	extra->nonvr = false;
}

static void init_cg(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_bb_cg_extra *bb_cg = NULL;
		SAFE_MALLOC(bb_cg, sizeof(struct ir_bb_cg_extra));
		// Empty bb cg
		bb->user_data = bb_cg;

		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			ir_init_insn_cg(env, insn);
			CHECK_ERR();
		}
	}

	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		ir_init_insn_cg(env, insn);
		CHECK_ERR();

		struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(insn);
		// Pre-colored registers are allocated
		extra->vr_pos.alloc_reg = i;
		extra->vr_pos.allocated = true;
		extra->nonvr = true;
	}
	ir_init_insn_cg(env, fun->sp);
	struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(fun->sp);
	extra->vr_pos.alloc_reg = 10;
	extra->vr_pos.allocated = true;
	extra->nonvr = true;
}

static void print_insn_extra(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_insn_cg_extra_v2 *insn_cg = insn->user_data;
	if (insn_cg == NULL) {
		CRITICAL("NULL user data");
	}
	struct ir_insn **pos;

	PRINT_LOG_DEBUG(env, "\nIn:");
	ptrset_for(pos, insn_cg->in)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG_DEBUG(env, " ");
		print_insn_ptr_base(env, insn);
	}
	PRINT_LOG_DEBUG(env, "\nOut:");
	ptrset_for(pos, insn_cg->out)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG_DEBUG(env, " ");
		print_insn_ptr_base(env, insn);
	}
	PRINT_LOG_DEBUG(env, "\n-------------\n");
}

static void print_ir_dst_v2(struct bpf_ir_env *env, struct ir_insn *insn)
{
	if (!insn->user_data) {
		PRINT_LOG_DEBUG(env, "(?)");
		RAISE_ERROR("NULL userdata found");
	}
	insn = insn_cg_v2(insn)->dst;
	if (insn) {
		print_insn_ptr_base(env, insn);
	} else {
		PRINT_LOG_DEBUG(env, "(NULL)");
	}
}

/*
SSA liveness analysis.

Algorithm from Florian Brandner, Benoit Boissinot, Alain Darte, Benoît Dupont de Dinechin, Fabrice Rastello. Computing Liveness Sets for SSA-Form Programs.

Section 5.2.

*/

static void up_and_mark(struct ir_insn *st, struct ir_insn *v)
{
}

static void in_out(struct bpf_ir_env *env, struct ir_function *fun)
{
}

static void liveness_analysis(struct bpf_ir_env *env, struct ir_function *fun)
{
	// TODO: Encode Calling convention into GEN KILL
	in_out(env, fun);
	if (env->opts.verbose > 2) {
		PRINT_LOG_DEBUG(env, "--------------\n");
		print_ir_prog_advanced(env, fun, NULL, print_insn_extra,
				       print_ir_dst_v2);
		print_ir_prog_advanced(env, fun, NULL, NULL, print_ir_dst_v2);
	}
}

void bpf_ir_compile(struct bpf_ir_env *env, struct ir_function *fun)
{
	init_cg(env, fun);
	CHECK_ERR();

	// Debugging settings
	fun->cg_info.spill_callee = 0;
}
