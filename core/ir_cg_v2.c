// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>
#include "ir_cg.h"

/*

Using SSA-based RA and graph coloring algorithm.

Algorithms are based on the following paper:

Pereira, F., and Palsberg, J., "Register Allocation via the Coloring of Chordal Graphs", APLAS, pp 315-329 (2005)

*/

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

static void set_insn_dst(struct ir_insn *insn, struct ir_insn *dst)
{
	insn_cg_v2(insn)->dst = dst;
}

static void pre_color(struct ir_function *fun, struct ir_insn *insn, u8 reg)
{
	set_insn_dst(insn, fun->cg_info.regs[reg]);
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
				insn_cg_v2(insn)->dst = NULL;
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

static void spill_array(struct bpf_ir_env *env, struct ir_function *fun)
{
	u32 offset = 0;
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
				offset -= (((size - 1) / 8) + 1) * 8;
				extra->vr_pos.spilled = offset;
				extra->vr_pos.spilled_size = size;
				extra->nonvr = true; // Array is not a VR
				extra->dst = NULL;
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
	print_insn_ptr_base(env, insn);
	insn = insn_cg_v2(insn)->dst;
	if (insn) {
		PRINT_LOG_DEBUG(env, "(");
		print_insn_ptr_base(env, insn);
		PRINT_LOG_DEBUG(env, ")");
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
	if (pos.spilled) {
		PRINT_LOG_DEBUG(env, "sp+%u", pos.spilled);
	} else {
		PRINT_LOG_DEBUG(env, "r%u", pos.alloc_reg);
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
			make_conflict(env, v, se->dst);
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

static void print_interference_graph(struct bpf_ir_env *env,
				     struct ir_function *fun)
{
	PRINT_LOG_DEBUG(env,
			"\x1B[32m----- CG: Interference Graph -----\x1B[0m\n");
	tag_ir(fun);
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

static void liveness_analysis(struct bpf_ir_env *env, struct ir_function *fun)
{
	bpf_ir_ptrset_clean(&fun->cg_info.all_var_v2);
	// Add all real registers to the graph
	for (int i = 0; i < RA_COLORS; ++i) {
		bpf_ir_ptrset_insert(env, &fun->cg_info.all_var_v2,
				     fun->cg_info.regs[i]);
	}

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
				if (extra->dst == v) {
					// dst is a VR
					bpf_ir_ptrset_insert(
						env, &fun->cg_info.all_var_v2,
						v);
				}

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

				if (v->op == IR_INSN_PHI) {
					// v is considered LIVE OUT for all preds
					struct phi_value *pos2;
					array_for(pos2, v->phi)
					{
						live_out_at_block(env, &M,
								  pos2->bb, v);
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

static void coloring(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct array sigma = mcs(env, fun);
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
	bpf_ir_array_free(&sigma);
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
			struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(v);
			if (v->op == IR_INSN_ASSIGN) {
				DBGASSERT(extra->dst);
				struct ir_insn *v2 = v->values[0].data.insn_d;
				struct ir_insn *v0 = extra->dst;
				struct ir_insn_cg_extra_v2 *extra_v0 =
					insn_cg_v2(v0);
				// v0 = v2
				if (extra_v0->vr_pos.spilled == 0 &&
				    v->values[0].type == IR_VALUE_INSN &&
				    insn_cg_v2(v2)->vr_pos.spilled == 0 &&
				    insn_cg_v2(v2)->vr_pos.alloc_reg !=
					    extra_v0->vr_pos.alloc_reg) {
					// Coalesce
					u8 used_colors[RA_COLORS] = { 0 };
					struct ir_insn **pos2;
					ptrset_for(pos2,
						   extra_v0->adj) // v0's adj
					{
						struct ir_insn *c = *pos2;
						struct ir_insn_cg_extra_v2 *cex =
							insn_cg_v2(c);
						DBGASSERT(
							cex->vr_pos.allocated);
						if (cex->vr_pos.spilled == 0) {
							used_colors
								[cex->vr_pos
									 .alloc_reg] =
									true;
						}
					}

					ptrset_for(
						pos2,
						insn_cg_v2(v2)->adj) // v2's adj
					{
						struct ir_insn *c = *pos2;
						struct ir_insn_cg_extra_v2 *cex =
							insn_cg_v2(c);
						DBGASSERT(
							cex->vr_pos.allocated);
						if (cex->vr_pos.spilled == 0) {
							used_colors
								[cex->vr_pos
									 .alloc_reg] =
									true;
						}
					}

					// There are three cases
					// 1. Rx = %y
					// 2. %x = Ry
					// 3. %x = %y

					if (extra_v0->nonvr) {
						if (!used_colors
							    [extra_v0->vr_pos
								     .alloc_reg]) {
							// Able to merge
							insn_cg_v2(v2)
								->vr_pos
								.alloc_reg =
								extra_v0->vr_pos
									.alloc_reg;
						}
					} else if (insn_cg_v2(v2)->nonvr) {
						if (!used_colors
							    [insn_cg_v2(v2)
								     ->vr_pos
								     .alloc_reg]) {
							extra_v0->vr_pos
								.alloc_reg =
								insn_cg_v2(v2)
									->vr_pos
									.alloc_reg;
						}
					} else {
						bool has_unused_color = false;
						u8 ureg = 0;
						for (u8 i = 0; i < RA_COLORS;
						     ++i) {
							if (!used_colors[i]) {
								has_unused_color =
									true;
								ureg = i;
								break;
							}
						}
						if (has_unused_color) {
							extra_v0->vr_pos
								.alloc_reg =
								ureg;
							insn_cg_v2(v2)
								->vr_pos
								.alloc_reg =
								ureg;
						}
					}
				}
			}
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
	init_cg(env, fun);
	CHECK_ERR();

	// Debugging settings
	fun->cg_info.spill_callee = 0;

	change_call(env, fun);
	change_fun_arg(env, fun);
	spill_array(env, fun);

	bool done = false;
	while (!done) {
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
			CRITICAL("todo");
		}
		bpf_ir_array_free(&to_spill);
	}

	// Graph coloring
	coloring(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_alloc(env, fun, "After Coloring");

	// Coalesce
	coalescing(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_alloc(env, fun, "After Coalescing");

	// SSA Out
	remove_phi(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_alloc(env, fun, "SSA Out");

	bpf_ir_cg_norm_v2(env, fun);
	CHECK_ERR();
	env->cg_time += get_cur_time_ns() - starttime;
}
