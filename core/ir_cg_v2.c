// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>
#include "ir_cg.h"

/*

Using SSA-based RA and graph coloring algorithm.

Algorithms are based on the following paper:

Pereira, F., and Palsberg, J., "Register Allocation via the Coloring of Chordal Graphs", APLAS, pp 315-329 (2005)

*/

/* CG Preparation Passes */
static struct function_pass cg_init_passes[] = {
	DEF_NON_OVERRIDE_FUNC_PASS(translate_throw, "translate_throw"),
	DEF_FUNC_PASS(bpf_ir_optimize_code_compaction, "optimize_compaction",
		      false),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_optimize_ir, "optimize_ir"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_cg_add_stack_offset_pre_cg,
				   "add_stack_offset"),
};

// Erase an instruction.
// Only used in SSA Out process.
// Do not use it within RA (it doesn not maintain adj and all_var stuff properly)
static void erase_insn_cg_v2(struct bpf_ir_env *env, struct ir_function *fun,
			     struct ir_insn *insn)
{
	if (insn->users.num_elem > 0) {
		struct ir_insn **pos;
		bool fail = false;
		array_for(pos, insn->users)
		{
			if (*pos != insn) {
				fail = true;
				break;
			}
		}
		if (fail) {
			tag_ir(fun);
			array_for(pos, insn->users)
			{
				print_ir_insn_err(env, *pos, "User");
			}
			print_ir_insn_err(env, insn, "Has users");
			RAISE_ERROR(
				"Cannot erase a instruction that has (non-self) users");
		}
	}
	struct array operands = bpf_ir_get_operands(env, insn);
	CHECK_ERR();
	struct ir_value **pos2;
	array_for(pos2, operands)
	{
		bpf_ir_val_remove_user((**pos2), insn);
	}
	bpf_ir_array_free(&operands);
	list_del(&insn->list_ptr);
	bpf_ir_array_free(&insn->users);

	struct ir_insn_cg_extra_v2 *extra = insn->user_data;
	bpf_ir_ptrset_free(&extra->adj);
	bpf_ir_ptrset_free(&extra->in);
	bpf_ir_ptrset_free(&extra->out);

	free_proto(insn);
}

static void remove_insn_dst(struct ir_insn *insn)
{
	insn_cg_v2(insn)->dst = NULL;
}

static void pre_color(struct ir_function *fun, struct ir_insn *insn, u8 reg)
{
	insn_cg_v2(insn)->finalized = true;
	insn_cg_v2(insn)->vr_pos.allocated = true;
	insn_cg_v2(insn)->vr_pos.alloc_reg = reg;
	insn_cg_v2(insn)->vr_pos.spilled = 0;
}

void bpf_ir_init_insn_cg_v2(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_insn_cg_extra_v2 *extra = NULL;
	SAFE_MALLOC(extra, sizeof(struct ir_insn_cg_extra_v2));
	insn->user_data = extra;

	extra->dst = bpf_ir_is_void(insn) ? NULL : insn;
	extra->vr_pos.allocated = false;
	extra->vr_pos.spilled = 0;
	extra->vr_pos.spilled_size = 0;
	extra->vr_pos.alloc_reg = 0;
	extra->finalized = false;
	extra->lambda = 0;
	extra->w = 0;

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
			bpf_ir_init_insn_cg_v2(env, insn);
			CHECK_ERR();
		}
	}

	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		bpf_ir_init_insn_cg_v2(env, insn);
		CHECK_ERR();

		struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(insn);
		// Pre-colored registers are allocated
		extra->vr_pos.alloc_reg = i;
		extra->vr_pos.allocated = true;
		extra->nonvr = true;
		extra->finalized = true;
	}
	bpf_ir_init_insn_cg_v2(env, fun->sp);
	struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(fun->sp);
	extra->vr_pos.alloc_reg = 10;
	extra->vr_pos.allocated = true;
	extra->nonvr = true;
	extra->finalized = true;
}

/*
Pre RA
*/

static void change_fun_arg(struct bpf_ir_env *env, struct ir_function *fun)
{
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		if (fun->function_arg[i]->users.num_elem > 0) {
			// Insert ASSIGN arg[i] at the beginning of the function
			struct ir_insn *new_insn =
				bpf_ir_create_assign_insn_bb_cg_v2(
					env, fun->entry,
					bpf_ir_value_insn(
						fun->cg_info.regs[i + 1]),
					INSERT_FRONT_AFTER_PHI);
			bpf_ir_replace_all_usage(env, fun->function_arg[i],
						 bpf_ir_value_insn(new_insn));
		}
	}
}

static void change_call(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_CALL) {
				// Change function call args
				for (u8 i = 0; i < insn->value_num; ++i) {
					struct ir_value val = insn->values[i];
					bpf_ir_val_remove_user(val, insn);
					struct ir_insn *new_insn =
						bpf_ir_create_assign_insn_cg_v2(
							env, insn, val,
							INSERT_FRONT);
					pre_color(fun, new_insn, i + 1);
				}
				insn->value_num = 0; // Remove all operands

				// Change function call dst
				remove_insn_dst(insn);
				if (insn->users.num_elem == 0) {
					continue;
				}
				struct ir_insn *new_insn =
					bpf_ir_create_assign_insn_cg_v2(
						env, insn,
						bpf_ir_value_insn(
							fun->cg_info.regs[0]),
						INSERT_BACK);
				bpf_ir_replace_all_usage(
					env, insn, bpf_ir_value_insn(new_insn));
			}
		}
	}
}

static inline s32 get_new_spill(struct ir_function *fun, u32 size)
{
	fun->cg_info.stack_offset -= size;
	return fun->cg_info.stack_offset;
}

static void spill_array(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (insn->op == IR_INSN_ALLOCARRAY) {
				struct ir_insn_cg_extra_v2 *extra =
					insn_cg_v2(insn);
				extra->vr_pos.allocated = true;
				// Calculate the offset
				u32 size = insn->array_num *
					   bpf_ir_sizeof_vr_type(insn->vr_type);
				if (size == 0) {
					RAISE_ERROR("Array size is 0");
				}
				// Round up to 8 bytes
				// u32 roundup_size = (((size - 1) / 8) + 1) * 8;
				u32 roundup_size = (size + 7) & ~7;
				extra->vr_pos.spilled =
					get_new_spill(fun, roundup_size);
				extra->vr_pos.spilled_size = size;
				extra->dst = NULL;
			}
		}
	}
}

// Spill constants based on BPF ISA
static void spill_const(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (bpf_ir_is_bin_alu(insn) &&
			    !bpf_ir_is_commutative_alu(insn)) {
				struct ir_value *val = &insn->values[0];
				if (val->type == IR_VALUE_CONSTANT) {
					// Change constant to a register
					struct ir_insn *new_insn =
						bpf_ir_create_assign_insn_cg_v2(
							env, insn, *val,
							INSERT_FRONT);
					bpf_ir_change_value(
						env, insn, val,
						bpf_ir_value_insn(new_insn));
				}
			}
			if (bpf_ir_is_cond_jmp(insn) && insn->value_num == 2) {
				// jmp v0 v1, cannot be all constants
				struct ir_value *v0 = &insn->values[1];
				struct ir_value *v1 = &insn->values[0];
				if (v0->type == IR_VALUE_CONSTANT &&
				    v1->type == IR_VALUE_CONSTANT) {
					// ==>
					// tmp = v0
					// jmp tmp v1
					struct ir_insn *new_insn =
						bpf_ir_create_assign_insn_cg_v2(
							env, insn, *v0,
							INSERT_FRONT);
					bpf_ir_change_value(
						env, insn, v0,
						bpf_ir_value_insn(new_insn));
				}
			}
		}
	}
}

/*
Print utils
*/

static void print_ir_dst_v2(struct bpf_ir_env *env, struct ir_insn *insn)
{
	if (!insn->user_data) {
		PRINT_LOG_DEBUG(env, "(?)");
		RAISE_ERROR("NULL userdata found");
	}
	insn = insn_cg_v2(insn)->dst;
	if (insn) {
		struct ir_vr_pos pos = insn_cg_v2(insn)->vr_pos;
		if (pos.allocated) {
			// Pre-colored
			if (pos.spilled) {
				PRINT_LOG_DEBUG(env, "SP+%d", pos.spilled);
			} else {
				PRINT_LOG_DEBUG(env, "R%u", pos.alloc_reg);
			}
		} else {
			print_insn_ptr_base(env, insn);
		}
	} else {
		PRINT_LOG_DEBUG(env, "(NULL)");
	}
}

static void print_ir_alloc_v2(struct bpf_ir_env *env, struct ir_insn *insn)
{
	if (!insn->user_data) {
		PRINT_LOG_DEBUG(env, "(?)");
		RAISE_ERROR("NULL userdata found");
	}
	if (insn_cg_v2(insn)->dst == NULL) {
		PRINT_LOG_DEBUG(env, "(NULL)");
		return;
	}
	struct ir_vr_pos pos = insn_cg_v2(insn)->vr_pos;
	DBGASSERT(pos.allocated);
	if (insn_cg_v2(insn)->finalized) {
		if (pos.spilled) {
			PRINT_LOG_DEBUG(env, "SP+%d", pos.spilled);
		} else {
			PRINT_LOG_DEBUG(env, "R%u", pos.alloc_reg);
		}
	} else {
		if (pos.spilled) {
			PRINT_LOG_DEBUG(env, "sp+%d", pos.spilled);
		} else {
			PRINT_LOG_DEBUG(env, "r%u", pos.alloc_reg);
		}
	}
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

/*
SSA liveness analysis.
*/

static void live_in_at_statement(struct bpf_ir_env *env,
				 struct ir_function *fun, struct ptrset *M,
				 struct ir_insn *s, struct ir_insn *v);

static void live_out_at_statement(struct bpf_ir_env *env,
				  struct ir_function *fun, struct ptrset *M,
				  struct ir_insn *s, struct ir_insn *v);

static void make_conflict(struct bpf_ir_env *env, struct ir_function *fun,
			  struct ir_insn *v1, struct ir_insn *v2)
{
	DBGASSERT(v1 != v2);
	struct ir_insn_cg_extra_v2 *v1e = insn_cg_v2(v1);
	struct ir_insn_cg_extra_v2 *v2e = insn_cg_v2(v2);
	struct ir_insn *r1 = v1;
	struct ir_insn *r2 = v2;
	if (v1e->finalized) {
		DBGASSERT(v1e->vr_pos.allocated);
	}
	if (v1e->vr_pos.allocated) {
		DBGASSERT(v1e->finalized);
		if (v1e->vr_pos.spilled) {
			// v1 is pre-spilled, no conflict
			return;
		} else {
			r1 = fun->cg_info.regs[v1e->vr_pos.alloc_reg];
		}
	}
	if (v2e->finalized) {
		DBGASSERT(v2e->vr_pos.allocated);
	}
	if (v2e->vr_pos.allocated) {
		DBGASSERT(v2e->finalized);
		if (v2e->vr_pos.spilled) {
			// v2 is pre-spilled, no conflict
			return;
		} else {
			r2 = fun->cg_info.regs[v2e->vr_pos.alloc_reg];
		}
	}
	struct ir_insn_cg_extra_v2 *r1e = insn_cg_v2(r1);
	struct ir_insn_cg_extra_v2 *r2e = insn_cg_v2(r2);
	bpf_ir_ptrset_insert(env, &r1e->adj, r2);
	bpf_ir_ptrset_insert(env, &r2e->adj, r1);
}

static void phi_conflict_at_block_no_propagate(struct bpf_ir_env *env,
					       struct ir_function *fun,
					       struct ir_basic_block *n,
					       struct ir_insn *v)
{
	struct ir_insn *last = bpf_ir_get_last_insn(n);
	if (last) {
		struct ptrset *set = NULL;
		struct ir_insn_cg_extra_v2 *se = insn_cg_v2(last);
		if (bpf_ir_is_jmp(last)) {
			// jmp xxx
			// Conflict with its LIVE-IN
			set = &se->in;
		} else {
			// Conflict with its LIVE-OUT
			set = &se->out;
		}
		struct ir_insn **pos;
		ptrset_for(pos, *set)
		{
			struct ir_insn *insn = *pos;
			if (insn != v) {
				make_conflict(env, fun, insn, v);
			}
		}
	} else {
		// Empty BB
		struct array preds = n->preds;
		struct ir_basic_block **pos;
		array_for(pos, preds)
		{
			phi_conflict_at_block_no_propagate(env, fun, *pos, v);
		}
	}
}

static void live_out_at_block(struct bpf_ir_env *env, struct ir_function *fun,
			      struct ptrset *M, struct ir_basic_block *n,
			      struct ir_insn *v)
{
	if (!bpf_ir_ptrset_exists(M, n)) {
		bpf_ir_ptrset_insert(env, M, n);
		struct ir_insn *last = bpf_ir_get_last_insn(n);
		if (last) {
			live_out_at_statement(env, fun, M, last, v);
		} else {
			// Empty BB
			struct array preds = n->preds;
			struct ir_basic_block **pos;
			array_for(pos, preds)
			{
				live_out_at_block(env, fun, M, *pos, v);
			}
		}
	}
}

static void live_out_at_statement(struct bpf_ir_env *env,
				  struct ir_function *fun, struct ptrset *M,
				  struct ir_insn *s, struct ir_insn *v)
{
	// PRINT_LOG_DEBUG(env, "%%%d live out at statement %%%d\n", v->_insn_id,
	// 		s->_insn_id);
	struct ir_insn_cg_extra_v2 *se = insn_cg_v2(s);
	bpf_ir_ptrset_insert(env, &se->out, v);
	if (se->dst) {
		if (se->dst != v) {
			make_conflict(env, fun, v, se->dst);
			live_in_at_statement(env, fun, M, s, v);
		}
	} else {
		// s has no dst (no KILL)
		live_in_at_statement(env, fun, M, s, v);
	}
}

static void live_in_at_statement(struct bpf_ir_env *env,
				 struct ir_function *fun, struct ptrset *M,
				 struct ir_insn *s, struct ir_insn *v)
{
	// PRINT_LOG_DEBUG(env, "%%%d live in at statement %%%d\n", v->_insn_id,
	// 		s->_insn_id);
	bpf_ir_ptrset_insert(env, &(insn_cg_v2(s))->in, v);
	struct ir_insn *prev = bpf_ir_prev_insn(s);
	if (prev == NULL) {
		// First instruction
		struct ir_basic_block **pos;
		array_for(pos, s->parent_bb->preds)
		{
			live_out_at_block(env, fun, M, *pos, v);
		}
	} else {
		live_out_at_statement(env, fun, M, prev, v);
	}
}

static void print_ir_prog_cg(struct bpf_ir_env *env, struct ir_function *fun,
			     char *msg)
{
	PRINT_LOG_DEBUG(env, "\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(env, fun, NULL, NULL, NULL);
}

static void print_ir_prog_cg_dst_liveness(struct bpf_ir_env *env,
					  struct ir_function *fun, char *msg)
{
	PRINT_LOG_DEBUG(env, "\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(env, fun, NULL, print_insn_extra,
			       print_ir_dst_v2);
}

static void print_ir_prog_cg_dst(struct bpf_ir_env *env,
				 struct ir_function *fun, char *msg)
{
	PRINT_LOG_DEBUG(env, "\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(env, fun, NULL, NULL, print_ir_dst_v2);
}

static void print_ir_prog_cg_alloc(struct bpf_ir_env *env,
				   struct ir_function *fun, char *msg)
{
	PRINT_LOG_DEBUG(env, "\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(env, fun, NULL, NULL, print_ir_alloc_v2);
}

static void print_insn_ptr_base_dot(struct bpf_ir_env *env,
				    struct ir_insn *insn)
{
	if (insn->op == IR_INSN_REG) {
		PRINT_LOG_DEBUG(env, "R%u", insn->reg_id);
		return;
	}
	if (insn->op == IR_INSN_FUNCTIONARG) {
		PRINT_LOG_DEBUG(env, "ARG%u", insn->fun_arg_id);
		return;
	}
	if (insn->_insn_id == SIZET_MAX) {
		PRINT_LOG_DEBUG(env, "PTR%p", insn);
		return;
	}
	PRINT_LOG_DEBUG(env, "VR%zu", insn->_insn_id);
}

static void print_interference_graph(struct bpf_ir_env *env,
				     struct ir_function *fun)
{
	PRINT_LOG_DEBUG(env,
			"\x1B[32m----- CG: Interference Graph -----\x1B[0m\n");
	tag_ir(fun);
	if (env->opts.dotgraph) {
		PRINT_LOG_DEBUG(env, "graph {\n");
		struct ir_insn **pos2;
		ptrset_for(pos2, fun->cg_info.all_var_v2)
		{
			struct ir_insn *v = *pos2;
			struct ir_insn **pos3;
			ptrset_for(pos3, insn_cg_v2(v)->adj)
			{
				PRINT_LOG_DEBUG(env, "\t");
				print_insn_ptr_base_dot(env, v);
				PRINT_LOG_DEBUG(env, " -- ");
				struct ir_insn *c = *pos3; // conflict vr
				print_insn_ptr_base_dot(env, c);
				PRINT_LOG_DEBUG(env, ";\n");
			}
		}
		PRINT_LOG_DEBUG(env, "}\n");
	} else {
		struct ir_insn **pos2;
		ptrset_for(pos2, fun->cg_info.all_var_v2)
		{
			struct ir_insn *v = *pos2;
			print_insn_ptr_base(env, v);
			PRINT_LOG_DEBUG(env, ": ");
			struct ir_insn **pos3;
			ptrset_for(pos3, insn_cg_v2(v)->adj)
			{
				struct ir_insn *c = *pos3; // conflict vr
				print_insn_ptr_base(env, c);
				PRINT_LOG_DEBUG(env, " ");
			}
			PRINT_LOG_DEBUG(env, "\n");
		}
	}
}

static void clean_cg_data_insn(struct ir_insn *insn)
{
	struct ir_insn_cg_extra_v2 *extra = insn->user_data;
	DBGASSERT(extra);
	bpf_ir_ptrset_clean(&extra->adj);
	bpf_ir_ptrset_clean(&extra->in);
	bpf_ir_ptrset_clean(&extra->out);
	extra->lambda = 0;
	extra->w = 0;

	if (!extra->finalized) {
		// Clean register allocation
		extra->vr_pos.allocated = false;
	}
}

// Clean data generated during each iteration of RA
static void clean_cg_data(struct bpf_ir_env *env, struct ir_function *fun)
{
	bpf_ir_ptrset_clean(&fun->cg_info.all_var_v2);
	// Add all real registers to the graph
	for (int i = 0; i < RA_COLORS; ++i) {
		bpf_ir_ptrset_insert(env, &fun->cg_info.all_var_v2,
				     fun->cg_info.regs[i]);
		clean_cg_data_insn(fun->cg_info.regs[i]);
	}

	// Note. there should be no use of function arg anymore as they are replaced by
	// %0 = R1
	// etc.

	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *v;
		list_for_each_entry(v, &bb->ir_insn_head, list_ptr) {
			clean_cg_data_insn(v);
		}
	}
}

static void liveness_analysis(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ptrset M;
	INIT_PTRSET_DEF(&M);
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *v;
		list_for_each_entry(v, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(v);

			if (extra->dst && !extra->finalized) {
				DBGASSERT(extra->dst == v);
				// Note. Assume pre-colored register VR has no users
				// dst is a VR
				bpf_ir_ptrset_insert(
					env, &fun->cg_info.all_var_v2, v);

				bpf_ir_ptrset_clean(&M);
				struct ir_insn **pos;
				array_for(pos, v->users)
				{
					struct ir_insn *s = *pos;
					if (s->op == IR_INSN_PHI) {
						struct phi_value *pos2;
						bool found = false;
						array_for(pos2, s->phi)
						{
							if (pos2->value.type ==
								    IR_VALUE_INSN &&
							    pos2->value.data.insn_d ==
								    v) {
								found = true;
								live_out_at_block(
									env,
									fun, &M,
									pos2->bb,
									v);
							}
						}
						if (!found) {
							CRITICAL(
								"Not found user!");
						}
					} else {
						live_in_at_statement(env, fun,
								     &M, s, v);
					}
				}
			}
		}
	}
	bpf_ir_ptrset_free(&M);

	print_ir_prog_cg_dst_liveness(env, fun, "Liveness");
}

static void caller_constraint(struct bpf_ir_env *env, struct ir_function *fun,
			      struct ir_insn *insn)
{
	for (u8 i = BPF_REG_0; i < BPF_REG_6; ++i) {
		// R0-R5 are caller saved register
		make_conflict(env, fun, fun->cg_info.regs[i], insn);
	}
}

static void conflict_analysis(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Add constraints to the graph

	for (u8 i = 0; i < RA_COLORS; ++i) {
		for (u8 j = i + 1; j < RA_COLORS; ++j) {
			// All physical registers are conflicting
			make_conflict(env, fun, fun->cg_info.regs[i],
				      fun->cg_info.regs[j]);
		}
	}

	struct ir_basic_block **pos;
	// For each BB
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		// For each operation
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra_v2 *insn_cg = insn->user_data;

			if (insn->op == IR_INSN_PHI) {
				// v conflicts with all its predecessors' LIVEOUT
				struct phi_value *pos2;
				array_for(pos2, insn->phi)
				{
					phi_conflict_at_block_no_propagate(
						env, fun, pos2->bb, insn);
				}
			}

			if (insn->op == IR_INSN_CALL) {
				// Add caller saved register constraints
				struct ir_insn **pos2;
				ptrset_for(pos2, insn_cg->in)
				{
					struct ir_insn **pos3;
					ptrset_for(pos3, insn_cg->out)
					{
						if (*pos2 == *pos3) {
							// Live across CALL!
							caller_constraint(
								env, fun,
								*pos2);
						}
					}
				}
			}
			if (bpf_ir_is_bin_alu(insn)) {
				// a = ALU b c
				if (insn->values[1].type == IR_VALUE_INSN) {
					make_conflict(
						env, fun, insn,
						insn->values[1].data.insn_d);
				}
			}
		}
	}
}

// Maximum cardinality search
static void mcs(struct bpf_ir_env *env, struct ir_function *fun)
{
	PRINT_LOG_DEBUG(env, "SEO: ");
	struct array *sigma = &fun->cg_info.seo;
	bpf_ir_array_clear(env, sigma);
	struct ptrset allvar;
	bpf_ir_ptrset_clone(env, &allvar, &fun->cg_info.all_var_v2);
	for (size_t i = 0; i < fun->cg_info.all_var_v2.cnt; ++i) {
		u32 max_l = 0;
		struct ir_insn *max_i = NULL;
		struct ir_insn **pos;
		ptrset_for(pos, allvar)
		{
			struct ir_insn_cg_extra_v2 *ex = insn_cg_v2(*pos);
			if (ex->lambda >= max_l) {
				max_l = ex->lambda;
				max_i = *pos;
			}
		}
		DBGASSERT(max_i != NULL);
		bpf_ir_array_push(env, sigma, &max_i);
		print_insn_ptr_base(env, max_i);
		PRINT_LOG_DEBUG(env, " ");

		struct ir_insn_cg_extra_v2 *max_iex = insn_cg_v2(max_i);
		ptrset_for(pos, max_iex->adj)
		{
			if (bpf_ir_ptrset_exists(&allvar, *pos)) {
				// *pos in allvar /\ N(max_i)
				insn_cg_v2(*pos)->lambda++;
			}
		}

		bpf_ir_ptrset_delete(&allvar, max_i);
	}

	bpf_ir_ptrset_free(&allvar);
	PRINT_LOG_DEBUG(env, "\n");
}

static struct ptrset *maxcl_need_spill(struct array *eps)
{
	struct ptrset *pos;
	array_for(pos, (*eps))
	{
		if (pos->cnt > RA_COLORS) {
			return pos;
		}
	}
	return NULL;
}

struct array pre_spill(struct bpf_ir_env *env, struct ir_function *fun)
{
	// First run maximalCl
	mcs(env, fun);
	struct array sigma = fun->cg_info.seo;
	struct array eps;
	INIT_ARRAY(&eps, struct ptrset);
	PRINT_LOG_DEBUG(env, "MaxCL:\n");
	for (size_t i = 0; i < sigma.num_elem; ++i) {
		PRINT_LOG_DEBUG(env, "%d: ", i);
		struct ir_insn *v = *array_get(&sigma, i, struct ir_insn *);
		struct ir_insn_cg_extra_v2 *vex = insn_cg_v2(v);
		struct ptrset q;
		INIT_PTRSET_DEF(&q);
		bpf_ir_ptrset_insert(env, &q, v);
		print_insn_ptr_base(env, v);
		PRINT_LOG_DEBUG(env, " ");
		vex->w++;
		struct ir_insn **pos;
		ptrset_for(pos, vex->adj)
		{
			struct ir_insn *u = *pos;

			for (size_t j = 0; j < i; ++j) {
				struct ir_insn *v2 =
					*array_get(&sigma, j, struct ir_insn *);
				if (v2 == u) {
					bpf_ir_ptrset_insert(env, &q, u);
					print_insn_ptr_base(env, u);
					PRINT_LOG_DEBUG(env, " ");
					insn_cg_v2(u)->w++;
					break;
				}
			}
		}
		PRINT_LOG_DEBUG(env, "\n");
		bpf_ir_array_push(env, &eps, &q);
	}

	PRINT_LOG_DEBUG(env, "To Spill:\n");
	struct ptrset *cur;
	struct array to_spill;
	INIT_ARRAY(&to_spill, struct ir_insn *);
	while ((cur = maxcl_need_spill(&eps))) {
		// cur has more than RA_COLORS nodes
		u32 max_w = 0;
		struct ir_insn *max_i = NULL;

		struct ir_insn **pos;
		ptrset_for(pos, (*cur))
		{
			struct ir_insn *v = *pos;
			struct ir_insn_cg_extra_v2 *vex = insn_cg_v2(v);
			if (vex->w >= max_w && !vex->nonvr) {
				// Must be a vr to be spilled
				max_w = vex->w;
				max_i = v;
			}
		}
		DBGASSERT(max_i != NULL);
		// Spill max_i
		bpf_ir_array_push(env, &to_spill, &max_i);

		PRINT_LOG_DEBUG(env, " ");
		print_insn_ptr_base(env, max_i);

		struct ptrset *pos2;
		array_for(pos2, eps)
		{
			bpf_ir_ptrset_delete(pos2, max_i);
		}
	}

	PRINT_LOG_DEBUG(env, "\n");
	struct ptrset *pos;
	array_for(pos, eps)
	{
		bpf_ir_ptrset_free(pos);
	}
	bpf_ir_array_free(&eps);
	return to_spill;
}

static struct ir_insn *cgir_load_stack(struct bpf_ir_env *env,
				       struct ir_function *fun,
				       struct ir_insn *insn,
				       struct ir_insn *alloc_insn)
{
	DBGASSERT(alloc_insn->op == IR_INSN_ALLOC);
	struct ir_insn *tmp = bpf_ir_create_load_insn_cg_v2(
		env, insn, bpf_ir_value_insn(alloc_insn), INSERT_FRONT);
	tmp->vr_type = alloc_insn->vr_type;
	return tmp;
}

static struct ir_insn *cgir_load_stack_bb_end(struct bpf_ir_env *env,
					      struct ir_function *fun,
					      struct ir_basic_block *bb,
					      struct ir_insn *alloc_insn)
{
	DBGASSERT(alloc_insn->op == IR_INSN_ALLOC);
	struct ir_insn *tmp = bpf_ir_create_load_insn_bb_cg_v2(
		env, bb, bpf_ir_value_insn(alloc_insn), INSERT_BACK_BEFORE_JMP);
	tmp->vr_type = alloc_insn->vr_type;
	return tmp;
}

static void spill_insn(struct bpf_ir_env *env, struct ir_function *fun,
		       struct ir_insn *insn, struct ir_insn *alloc_insn,
		       struct ir_insn *v)
{
	// INSN is spilled on stack
	if (insn->op == IR_INSN_STORE &&
	    bpf_ir_value_equal(insn->values[0], bpf_ir_value_insn(insn))) {
		// store INSN xxx
	} else if (insn->op == IR_INSN_LOAD &&
		   bpf_ir_value_equal(insn->values[0],
				      bpf_ir_value_insn(insn))) {
		// load INSN
	} else if (insn->op == IR_INSN_PHI) {
		struct phi_value *val;
		array_for(val, insn->phi)
		{
			if (val->value.type == IR_VALUE_INSN &&
			    val->value.data.insn_d == v) {
				// val uses v, spill it
				struct ir_insn *spilled_load =
					cgir_load_stack_bb_end(
						env, fun, val->bb, alloc_insn);
				bpf_ir_change_value(
					env, insn, &val->value,
					bpf_ir_value_insn(spilled_load));
			}
		}
	} else {
		// General case
		struct ir_insn *spilled_load =
			cgir_load_stack(env, fun, insn, alloc_insn);

		struct array uses = bpf_ir_get_operands(env, insn);
		struct ir_value **pos;

		array_for(pos, uses)
		{
			struct ir_value *val = *pos;
			if (val->type == IR_VALUE_INSN &&
			    val->data.insn_d == v) {
				// val uses v, spill it
				bpf_ir_change_value(
					env, insn, val,
					bpf_ir_value_insn(spilled_load));
			}
		}

		bpf_ir_array_free(&uses);
	}
	CHECK_ERR();
}

static void spill(struct bpf_ir_env *env, struct ir_function *fun,
		  struct array *to_spill)
{
	struct ir_insn **pos;
	array_for(pos, (*to_spill))
	{
		struct ir_insn *v = *pos;

		// v = ...
		// ==>
		// %1 = alloc <pos>
		// ..
		// %tmp = ...
		// store %1, %tmp

		struct ir_insn *alloc_insn;

		DBGASSERT(v->op != IR_INSN_CALL);
		DBGASSERT(v->op != IR_INSN_ALLOCARRAY);

		// First clone a copy of users
		struct array users;
		bpf_ir_array_clone(env, &users, &v->users);

		if (v->op == IR_INSN_ALLOC) {
			// spill load and store instruction
			alloc_insn = v;
		} else {
			alloc_insn = bpf_ir_create_alloc_insn_bb_cg_v2(
				env, fun->entry, IR_VR_TYPE_64,
				INSERT_FRONT_AFTER_PHI);

			struct ir_insn *store_insn =
				bpf_ir_create_store_insn_cg_v2(
					env, v, alloc_insn,
					bpf_ir_value_insn(v), INSERT_BACK);
			DBGASSERT(insn_dst_v2(store_insn) == NULL);
		}

		// Finalize stack spilled value
		// so that it will not change in next iteration
		insn_cg_v2(alloc_insn)->finalized = true;
		insn_cg_v2(alloc_insn)->vr_pos.allocated = true;
		insn_cg_v2(alloc_insn)->vr_pos.spilled = get_new_spill(fun, 8);
		insn_cg_v2(alloc_insn)->vr_pos.spilled_size = 8;

		// Spill every user of v (spill-everywhere algorithm)

		struct ir_insn **pos2;
		array_for(pos2, users)
		{
			spill_insn(env, fun, *pos2, alloc_insn, v);
			CHECK_ERR();
		}

		bpf_ir_array_free(&users);
	}
}

static void coloring(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct array sigma = fun->cg_info.seo;
	struct ir_insn **pos;

	array_for(pos, sigma)
	{
		struct ir_insn *v = *pos;
		struct ir_insn_cg_extra_v2 *vex = insn_cg_v2(v);
		if (vex->vr_pos.allocated) {
			continue;
		}

		bool used_reg[RA_COLORS] = { 0 };
		struct ir_insn **pos2;
		ptrset_for(pos2, vex->adj)
		{
			struct ir_insn *insn2 = *pos2; // Adj instruction
			struct ir_insn_cg_extra_v2 *extra2 = insn_cg_v2(insn2);
			if (extra2->vr_pos.allocated &&
			    extra2->vr_pos.spilled == 0) {
				used_reg[extra2->vr_pos.alloc_reg] = true;
			}
		}

		for (u8 i = 0; i < RA_COLORS; i++) {
			if (!used_reg[i]) {
				vex->vr_pos.allocated = true;
				vex->vr_pos.alloc_reg = i;
				break;
			}
		}
		if (!vex->vr_pos.allocated) {
			RAISE_ERROR("No register available");
		}
	}
}

// static bool has_conflict(struct ir_insn *v1, struct ir_insn *v2)
// {
// 	return bpf_ir_ptrset_exists(&insn_cg_v2(v1)->adj, v2);
// }

static void coalesce(struct ir_insn *v1, struct ir_insn *v2)
{
	struct ir_insn_cg_extra_v2 *v1e = insn_cg_v2(v1);
	struct ir_insn_cg_extra_v2 *v2e = insn_cg_v2(v2);
	if (v1e->vr_pos.spilled == 0 && v2e->vr_pos.spilled == 0 &&
	    v2e->vr_pos.alloc_reg != v1e->vr_pos.alloc_reg) {
		// Coalesce
		u8 used_colors[RA_COLORS] = { 0 };
		struct ir_insn **pos2;
		ptrset_for(pos2, v1e->adj) // v1's adj
		{
			struct ir_insn *c = *pos2;
			struct ir_insn_cg_extra_v2 *cex = insn_cg_v2(c);
			DBGASSERT(cex->vr_pos.allocated);
			if (cex->vr_pos.spilled == 0) {
				used_colors[cex->vr_pos.alloc_reg] = true;
			}
		}

		ptrset_for(pos2, v2e->adj) // v2's adj
		{
			struct ir_insn *c = *pos2;
			struct ir_insn_cg_extra_v2 *cex = insn_cg_v2(c);
			DBGASSERT(cex->vr_pos.allocated);
			if (cex->vr_pos.spilled == 0) {
				used_colors[cex->vr_pos.alloc_reg] = true;
			}
		}

		// There are three cases
		// 1. Rx = %y
		// 2. %x = Ry
		// 3. %x = %y

		if (v1e->finalized) {
			if (!used_colors[v1e->vr_pos.alloc_reg]) {
				// Able to merge
				v2e->vr_pos.alloc_reg = v1e->vr_pos.alloc_reg;
			}
		} else if (v2e->finalized) {
			if (!used_colors[v2e->vr_pos.alloc_reg]) {
				v1e->vr_pos.alloc_reg = v2e->vr_pos.alloc_reg;
			}
		} else {
			bool has_unused_color = false;
			u8 ureg = 0;
			for (u8 i = 0; i < RA_COLORS; ++i) {
				if (!used_colors[i]) {
					has_unused_color = true;
					ureg = i;
					break;
				}
			}
			if (has_unused_color) {
				v1e->vr_pos.alloc_reg = ureg;
				v2e->vr_pos.alloc_reg = ureg;
			}
		}
	}
}

// Best effort coalescing
static void coalescing(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *v;
		list_for_each_entry(v, &bb->ir_insn_head, list_ptr) {
			struct ir_insn *v1 = v;
			struct ir_insn *v2 = NULL;
			// v1 = v2
			if (v1->op == IR_INSN_ASSIGN) {
				if (v1->values[0].type != IR_VALUE_INSN) {
					continue;
				}
				v2 = v1->values[0].data.insn_d;
				coalesce(v1, v2);
			} else if (v1->op == IR_INSN_STORE) {
				// store v[0], v[1]
				DBGASSERT(v1->values[0].type == IR_VALUE_INSN);
				DBGASSERT(v1->values[0].data.insn_d->op ==
					  IR_INSN_ALLOC);
				if (v1->values[1].type != IR_VALUE_INSN) {
					continue;
				}
				v2 = v1->values[1].data.insn_d;
				v1 = v1->values[0].data.insn_d;
				coalesce(v1, v2);
			} else if (v1->op == IR_INSN_LOAD) {
				// v = load val[0]
				DBGASSERT(v1->values[0].type == IR_VALUE_INSN);
				DBGASSERT(v1->values[0].data.insn_d->op ==
					  IR_INSN_ALLOC);
				v2 = v1->values[0].data.insn_d;
				coalesce(v1, v2);
			}
			CHECK_ERR();
		}
	}
}

static void add_stack_offset(struct bpf_ir_env *env, struct ir_function *fun,
			     s16 offset)
{
	struct ir_basic_block **pos;
	// For each BB
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		// For each operation
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_LOADRAW ||
			    insn->op == IR_INSN_STORERAW) {
				if (insn->addr_val.offset_type ==
				    IR_VALUE_CONSTANT_RAWOFF) {
					insn->addr_val.offset += offset;
					insn->addr_val.offset_type =
						IR_VALUE_CONSTANT;
					continue;
				} else if (insn->addr_val.offset_type ==
					   IR_VALUE_CONSTANT_RAWOFF_REV) {
					insn->addr_val.offset -= offset;
					insn->addr_val.offset_type =
						IR_VALUE_CONSTANT;
					continue;
				}
			}
			struct array value_uses =
				bpf_ir_get_operands(env, insn);
			struct ir_value **pos2;
			array_for(pos2, value_uses)
			{
				struct ir_value *val = *pos2;
				if (val->type == IR_VALUE_CONSTANT_RAWOFF) {
					// Stack pointer as value
					val->data.constant_d += offset;
					val->type = IR_VALUE_CONSTANT;
				} else if (val->type ==
					   IR_VALUE_CONSTANT_RAWOFF_REV) {
					val->data.constant_d -= offset;
					val->type = IR_VALUE_CONSTANT;
				}
			}
			bpf_ir_array_free(&value_uses);
		}
	}
}

// Remove PHI insn
// Move out from SSA form
static void remove_phi(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct array phi_insns;
	INIT_ARRAY(&phi_insns, struct ir_insn *);

	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_PHI) {
				DBGASSERT(insn_cg_v2(insn)->dst);
				// Phi cannot be spilled
				DBGASSERT(insn_cg_v2(insn_cg_v2(insn)->dst)
						  ->vr_pos.spilled == 0);
				bpf_ir_array_push(env, &phi_insns, &insn);
			} else {
				break;
			}
		}
	}

	struct ir_insn **pos2;
	array_for(pos2, phi_insns)
	{
		struct ir_insn *insn = *pos2;

		struct ir_vr_pos vrpos = insn_cg_v2(insn)->vr_pos;

		struct phi_value *pos3;
		array_for(pos3, insn->phi)
		{
			struct ir_insn *new_insn =
				bpf_ir_create_assign_insn_bb_cg_v2(
					env, pos3->bb, pos3->value,
					INSERT_BACK_BEFORE_JMP);

			insn_cg_v2(new_insn)->vr_pos = vrpos;

			// Remove use
			bpf_ir_val_remove_user(pos3->value, insn);
		}

		bpf_ir_array_free(&insn->phi);

		bpf_ir_replace_all_usage_cg(
			env, insn,
			bpf_ir_value_insn(fun->cg_info.regs[vrpos.alloc_reg]));
		erase_insn_cg_v2(env, fun, insn);
	}

	bpf_ir_array_free(&phi_insns);
}

void bpf_ir_compile_v2(struct bpf_ir_env *env, struct ir_function *fun)
{
	u64 starttime = get_cur_time_ns();

	bpf_ir_run_passes(env, fun, cg_init_passes,
			  sizeof(cg_init_passes) / sizeof(cg_init_passes[0]));
	CHECK_ERR();

	init_cg(env, fun);
	CHECK_ERR();

	// Debugging settings
	fun->cg_info.spill_callee = 0;

	change_call(env, fun);
	CHECK_ERR();
	print_ir_prog_cg(env, fun, "After Change call");

	change_fun_arg(env, fun);
	CHECK_ERR();
	print_ir_prog_cg(env, fun, "After Change fun");

	spill_array(env, fun);
	CHECK_ERR();
	print_ir_prog_cg(env, fun, "After Spill Array");

	spill_const(env, fun);
	CHECK_ERR();
	print_ir_prog_cg(env, fun, "After Spill Const");

	bpf_ir_cg_prog_check(env, fun);
	CHECK_ERR();

	bool done = false;
	u32 iteration = 0;
	while (!done) {
		if (iteration > 5) {
			RAISE_ERROR("Too many iterations");
		}
		PRINT_LOG_DEBUG(
			env,
			"\x1B[32m----- Register allocation iteration %d -----\x1B[0m\n",
			iteration);
		clean_cg_data(env, fun);
		liveness_analysis(env, fun);
		print_interference_graph(env, fun);

		print_ir_prog_cg_dst(env, fun, "After liveness");

		conflict_analysis(env, fun);
		print_interference_graph(env, fun);

		struct array to_spill = pre_spill(env, fun);
		if (to_spill.num_elem == 0) {
			// No need to spill
			done = true;
		} else {
			// spill
			spill(env, fun, &to_spill);
			bpf_ir_prog_check(env, fun);
			CHECK_ERR();
			print_ir_prog_cg_dst(env, fun, "After Spill");
		}
		bpf_ir_array_free(&to_spill);
		iteration++;
	}

	PRINT_LOG_DEBUG(env, "RA finished in %u iterations\n", iteration);

	// Graph coloring
	coloring(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_alloc(env, fun, "After Coloring");

	if (!env->opts.disable_coalesce) {
		// Coalesce
		coalescing(env, fun);
		CHECK_ERR();
		print_ir_prog_cg_alloc(env, fun, "After Coalescing");
	}

	add_stack_offset(env, fun, fun->cg_info.stack_offset);

	// SSA Out
	remove_phi(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_alloc(env, fun, "SSA Out");

	bpf_ir_cg_norm_v2(env, fun);
	CHECK_ERR();
	env->cg_time += get_cur_time_ns() - starttime;
}
