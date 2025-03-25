// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>
#include "ir_cg.h"

/*

Using SSA-based RA and graph coloring algorithm.

Algorithms are based on the following paper:

Pereira, F., and Palsberg, J., "Register Allocation via the Coloring of Chordal Graphs", APLAS, pp 315-329 (2005)

*/

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
	}
	bpf_ir_init_insn_cg_v2(env, fun->sp);
	struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(fun->sp);
	extra->vr_pos.alloc_reg = 10;
	extra->vr_pos.allocated = true;
	extra->nonvr = true;
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

static void live_in_at_statement(struct bpf_ir_env *env, struct ptrset *M,
				 struct ir_insn *s, struct ir_insn *v);

static void live_out_at_statement(struct bpf_ir_env *env, struct ptrset *M,
				  struct ir_insn *s, struct ir_insn *v);

static void make_conflict(struct bpf_ir_env *env, struct ir_insn *v1,
			  struct ir_insn *v2)
{
	struct ir_insn_cg_extra_v2 *v1e = insn_cg_v2(v1);
	struct ir_insn_cg_extra_v2 *v2e = insn_cg_v2(v2);
	bpf_ir_ptrset_insert(env, &v1e->adj, v2);
	bpf_ir_ptrset_insert(env, &v2e->adj, v1);
}

static void live_out_at_block(struct bpf_ir_env *env, struct ptrset *M,
			      struct ir_basic_block *n, struct ir_insn *v)
{
	if (!bpf_ir_ptrset_exists(M, n)) {
		bpf_ir_ptrset_insert(env, M, n);
		struct ir_insn *last = bpf_ir_get_last_insn(n);
		if (last) {
			live_out_at_statement(env, M, last, v);
		} else {
			// Empty BB
			struct array preds = n->preds;
			struct ir_basic_block **pos;
			array_for(pos, preds)
			{
				live_out_at_block(env, M, *pos, v);
			}
		}
	}
}

static void live_out_at_statement(struct bpf_ir_env *env, struct ptrset *M,
				  struct ir_insn *s, struct ir_insn *v)
{
	struct ir_insn_cg_extra_v2 *se = insn_cg_v2(s);
	bpf_ir_ptrset_insert(env, &se->out, v);
	if (se->dst) {
		if (se->dst != v) {
			make_conflict(env, v, s);
			live_in_at_statement(env, M, s, v);
		}
	} else {
		// s has no dst (no KILL)
		live_in_at_statement(env, M, s, v);
	}
}

static void live_in_at_statement(struct bpf_ir_env *env, struct ptrset *M,
				 struct ir_insn *s, struct ir_insn *v)
{
	bpf_ir_ptrset_insert(env, &(insn_cg_v2(s))->in, v);
	struct ir_insn *prev = bpf_ir_prev_insn(s);
	if (prev == NULL) {
		// First instruction
		struct ir_basic_block **pos;
		array_for(pos, s->parent_bb->preds)
		{
			live_out_at_block(env, M, *pos, v);
		}
	} else {
		live_out_at_statement(env, M, prev, v);
	}
}

static void print_ir_prog_cg_dst(struct bpf_ir_env *env,
				 struct ir_function *fun, char *msg)
{
	PRINT_LOG_DEBUG(env, "\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(env, fun, NULL, print_insn_extra,
			       print_ir_dst_v2);
}

static void liveness_analysis(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Assumption: dst = insn
	bpf_ir_ptrset_clean(&fun->cg_info.all_var_v2);
	struct ptrset M;
	INIT_PTRSET_DEF(&M);
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *v;
		list_for_each_entry(v, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(v);
			// Clean
			extra->lambda = 0;
			extra->w = 0;

			if (extra->dst) {
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
									env, &M,
									pos2->bb,
									v);
								break;
							}
						}
						if (!found) {
							CRITICAL(
								"Not found user!");
						}
					} else {
						live_in_at_statement(env, &M, s,
								     v);
					}
				}
			}
		}
	}
	bpf_ir_ptrset_free(&M);

	// Debug
	print_ir_prog_cg_dst(env, fun, "Conflict analysis");
	struct ir_insn **pos2;
	ptrset_for(pos2, fun->cg_info.all_var_v2)
	{
		struct ir_insn *v = *pos2;
		PRINT_LOG_DEBUG(env, "%%%d: ", v->_insn_id);
		struct ir_insn **pos3;
		ptrset_for(pos3, insn_cg_v2(v)->adj)
		{
			struct ir_insn *c = *pos3; // conflict vr
			PRINT_LOG_DEBUG(env, "%%%d ", c->_insn_id);
		}
		PRINT_LOG_DEBUG(env, "\n");
	}
}

static void caller_constraint(struct bpf_ir_env *env, struct ir_function *fun,
			      struct ir_insn *insn)
{
	for (u8 i = BPF_REG_0; i < BPF_REG_6; ++i) {
		// R0-R5 are caller saved register
		make_conflict(env, fun->cg_info.regs[i], insn);
	}
}

static void conflict_analysis(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Add constraints to the graph

	struct ir_basic_block **pos;
	// For each BB
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		// For each operation
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra_v2 *insn_cg = insn->user_data;
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
		}
	}
}

// Maximum cardinality search
static struct array mcs(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct array sigma;
	INIT_ARRAY(&sigma, struct ir_insn *);
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
		bpf_ir_array_push(env, &sigma, &max_i);

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
	return sigma;
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
	struct array sigma = mcs(env, fun);
	struct array eps;
	INIT_ARRAY(&eps, struct ptrset);
	for (size_t i = 0; i < sigma.num_elem; ++i) {
		struct ir_insn *v = *array_get(&sigma, i, struct ir_insn *);
		struct ir_insn_cg_extra_v2 *vex = insn_cg_v2(v);
		struct ptrset q;
		INIT_PTRSET_DEF(&q);
		bpf_ir_ptrset_insert(env, &q, v);
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
					insn_cg_v2(u)->w++;
					break;
				}
			}
		}
		bpf_ir_array_push(env, &eps, &q);
	}

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

		struct ptrset *pos2;
		array_for(pos2, eps)
		{
			bpf_ir_ptrset_delete(pos2, max_i);
		}
	}

	struct ptrset *pos;
	array_for(pos, eps)
	{
		bpf_ir_ptrset_free(pos);
	}
	bpf_ir_array_free(&eps);
	bpf_ir_array_free(&sigma);
	return to_spill;
}

static void spill(struct bpf_ir_env *env, struct ir_function *fun,
		  struct array *to_spill)
{
}

void bpf_ir_compile_v2(struct bpf_ir_env *env, struct ir_function *fun)
{
	init_cg(env, fun);
	CHECK_ERR();

	// Debugging settings
	fun->cg_info.spill_callee = 0;

	bool done = false;

	while (!done) {
		liveness_analysis(env, fun);
		conflict_analysis(env, fun);
		struct array to_spill = pre_spill(env, fun);
		if (to_spill.num_elem == 0) {
			// No need to spill
			done = true;
		} else {
			// spill
		}
		bpf_ir_array_free(&to_spill);
	}

	// Graph coloring

	// Coalesce

	CRITICAL("done");
}
