// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/bpf_ir.h>

static void set_insn_dst(struct bpf_ir_env *env, struct ir_insn *insn,
			 struct ir_insn *dst)
{
	struct ir_value v = dst ? bpf_ir_value_insn(dst) : bpf_ir_value_undef();
	if (insn_cg(insn)->dst.type == IR_VALUE_INSN) {
		// Remove previous user
		// Change all users to new dst (used in coalescing)
		bpf_ir_replace_all_usage_cg(env, insn, v);
	} else {
		bpf_ir_val_add_user(env, v, insn);
	}
	insn_cg(insn)->dst = v;
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
			bpf_ir_init_insn_cg(env, insn);
			CHECK_ERR();
		}
	}

	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		bpf_ir_init_insn_cg(env, insn);
		CHECK_ERR();

		struct ir_insn_cg_extra *extra = insn_cg(insn);
		extra->alloc_reg = i;
		// Pre-colored registers are allocated
		extra->allocated = true;
		extra->spilled = 0;
		extra->spilled_size = 0;
		extra->nonvr = true;
	}
	bpf_ir_init_insn_cg(env, fun->sp);
	struct ir_insn_cg_extra *extra = insn_cg(fun->sp);
	extra->alloc_reg = 10;
	extra->allocated = true;
	extra->spilled = 0;
	extra->spilled_size = 0;
	extra->nonvr = true;
}

void bpf_ir_free_insn_cg(struct ir_insn *insn)
{
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	bpf_ir_array_free(&extra->adj);
	bpf_ir_array_free(&extra->gen);
	bpf_ir_array_free(&extra->kill);
	bpf_ir_array_free(&extra->in);
	bpf_ir_array_free(&extra->out);
	free_proto(extra);
	insn->user_data = NULL;
}

static void free_cg_res(struct ir_function *fun)
{
	struct ir_basic_block **pos = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_bb_cg_extra *bb_cg = bb->user_data;
		free_proto(bb_cg);
		bb->user_data = NULL;
		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			bpf_ir_free_insn_cg(insn);
		}
	}

	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		bpf_ir_free_insn_cg(insn);
	}
	bpf_ir_free_insn_cg(fun->sp);
}

static void clean_insn_cg(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	bpf_ir_array_clear(env, &extra->adj);
	bpf_ir_array_clear(env, &extra->gen);
	bpf_ir_array_clear(env, &extra->kill);
	bpf_ir_array_clear(env, &extra->in);
	bpf_ir_array_clear(env, &extra->out);
}

static void clean_cg(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			clean_insn_cg(env, insn);
			struct ir_insn_cg_extra *extra = insn_cg(insn);
			if (insn->op != IR_INSN_ALLOCARRAY) {
				extra->allocated = false;
				extra->spilled = 0;
				extra->spilled_size = 0;
				extra->alloc_reg = 0;
			}
		}
	}

	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		clean_insn_cg(env, insn);
	}
	clean_insn_cg(env, fun->sp); // But should have no effect I guess?
	bpf_ir_array_clear(env, &fun->cg_info.all_var);
}

static void print_ir_prog_cg_dst(struct bpf_ir_env *env,
				 struct ir_function *fun, char *msg)
{
	PRINT_LOG(env, "\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(env, fun, NULL, NULL, print_ir_dst);
}

static void print_ir_prog_cg_alloc(struct bpf_ir_env *env,
				   struct ir_function *fun, char *msg)
{
	PRINT_LOG(env, "\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(env, fun, NULL, NULL, print_ir_alloc);
}

static void synthesize(struct bpf_ir_env *env, struct ir_function *fun)
{
	// The last step, synthesizes the program
	SAFE_MALLOC(env->insns, env->insn_cnt * sizeof(struct bpf_insn));
	struct ir_basic_block **pos = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra *extra = insn_cg(insn);
			for (u8 i = 0; i < extra->translated_num; ++i) {
				struct pre_ir_insn translated_insn =
					extra->translated[i];
				// PRINT_DBG("Writing to insn %zu\n",
				// 	  translated_insn.pos);
				struct bpf_insn *real_insn =
					&env->insns[translated_insn.pos];
				real_insn->code = translated_insn.opcode;
				real_insn->dst_reg = translated_insn.dst_reg;
				real_insn->src_reg = translated_insn.src_reg;
				real_insn->off = translated_insn.off;
				if (translated_insn.it == IMM) {
					real_insn->imm = translated_insn.imm;
				} else {
					// Wide instruction
					struct bpf_insn *real_insn2 =
						&env->insns[translated_insn.pos +
							    1];
					real_insn->imm = translated_insn.imm64 &
							 0xffffffff;
					real_insn2->imm =
						translated_insn.imm64 >> 32;
				}
			}
		}
	}
}

// Remove PHI insn
static void remove_phi(struct bpf_ir_env *env, struct ir_function *fun)
{
	// dst information ready
	struct array phi_insns;
	INIT_ARRAY(&phi_insns, struct ir_insn *);

	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_PHI) {
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
		struct ir_insn *repr = NULL;
		struct phi_value *pos3;
		array_for(pos3, insn->phi)
		{
			DBGASSERT(pos3->value.type == IR_VALUE_INSN);
			if (!repr) {
				repr = pos3->value.data.insn_d;
			} else {
				set_insn_dst(env, pos3->value.data.insn_d,
					     repr);
			}
		}
		if (!repr) {
			CRITICAL("Empty Phi not removed!");
		}

		DBGASSERT(repr == insn_dst(repr));

		bpf_ir_replace_all_usage_cg(env, insn, bpf_ir_value_insn(repr));
		bpf_ir_erase_insn_cg(env, fun, insn);
	}

	bpf_ir_array_free(&phi_insns);
}

static bool is_insn_final(struct ir_insn *v1)
{
	return v1 == insn_dst(v1);
}

static void build_conflict(struct bpf_ir_env *env, struct ir_insn *v1,
			   struct ir_insn *v2)
{
	if (!is_insn_final(v1) || !is_insn_final(v2)) {
		CRITICAL("Can only build conflict on final values");
	}
	if (v1 == v2) {
		return;
	}
	bpf_ir_array_push_unique(env, &insn_cg(v1)->adj, &v2);
	bpf_ir_array_push_unique(env, &insn_cg(v2)->adj, &v1);
}

static void bpf_ir_print_interference_graph(struct bpf_ir_env *env,
					    struct ir_function *fun)
{
	// Tag the IR to have the actual number to print
	tag_ir(fun);
	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn *insn = *pos;
		if (insn->op == IR_INSN_REG) {
			CRITICAL(
				"Pre-colored register should not be in all_var");
		}
		struct ir_insn_cg_extra *extra = insn_cg(insn);
		if (!is_insn_final(extra->dst.data.insn_d)) {
			// Not final value, give up
			print_ir_insn_err_full(env, insn, "Instruction",
					       print_ir_dst);
			RAISE_ERROR("Not Final Value!");
		}
		if (extra->allocated) {
			// Allocated VR
			PRINT_LOG(env, "%%%zu(", insn->_insn_id);
			if (extra->spilled) {
				PRINT_LOG(env, "sp+%d", extra->spilled);
			} else {
				PRINT_LOG(env, "r%u", extra->alloc_reg);
			}
			PRINT_LOG(env, "):");
		} else {
			// Pre-colored registers or unallocated VR
			print_insn_ptr_base(env, insn);
			PRINT_LOG(env, ":");
		}
		struct ir_insn **pos2;
		array_for(pos2, insn_cg(insn)->adj)
		{
			struct ir_insn *adj_insn = *pos2;
			if (!is_insn_final(adj_insn)) {
				// Not final value, give up
				CRITICAL("Not Final Value!");
			}
			PRINT_LOG(env, " ");
			print_insn_ptr_base(env, adj_insn);
		}
		PRINT_LOG(env, "\n");
	}
}

static void caller_constraint(struct bpf_ir_env *env, struct ir_function *fun,
			      struct ir_insn *insn)
{
	for (u8 i = BPF_REG_0; i < BPF_REG_6; ++i) {
		// R0-R5 are caller saved register
		DBGASSERT(fun->cg_info.regs[i] ==
			  insn_dst(fun->cg_info.regs[i]));
		build_conflict(env, fun->cg_info.regs[i], insn);
	}
}

static void conflict_analysis(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Basic conflict:
	// For every x in KILL set, x is conflict with every element in OUT set.

	struct ir_basic_block **pos;
	// For each BB
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		// For each operation
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra *insn_cg = insn->user_data;
			if (insn->op == IR_INSN_CALL) {
				// Add caller saved register constraints
				struct ir_insn **pos2;
				array_for(pos2, insn_cg->in)
				{
					DBGASSERT(*pos2 == insn_dst(*pos2));
					struct ir_insn **pos3;
					array_for(pos3, insn_cg->out)
					{
						DBGASSERT(*pos3 ==
							  insn_dst(*pos3));
						if (*pos2 == *pos3) {
							// Live across CALL!
							// PRINT_LOG("Found a VR live across CALL!\n");
							caller_constraint(
								env, fun,
								*pos2);
						}
					}
				}
			}
			struct ir_insn **pos2;
			array_for(pos2, insn_cg->kill)
			{
				struct ir_insn *insn_dst = *pos2;
				DBGASSERT(insn_dst == insn_dst(insn_dst));
				if (insn_dst->op != IR_INSN_REG) {
					bpf_ir_array_push_unique(
						env, &fun->cg_info.all_var,
						&insn_dst);
				}
				struct ir_insn **pos3;
				array_for(pos3, insn_cg->out)
				{
					DBGASSERT(*pos3 == insn_dst(*pos3));
					build_conflict(env, insn_dst, *pos3);
				}
			}
		}
	}
}

static u8 allocated_reg_insn(struct ir_insn *insn)
{
	return insn_cg(insn)->alloc_reg;
}

static u8 allocated_reg(struct ir_value val)
{
	// DBGASSERT(val.type == IR_VALUE_INSN);
	return allocated_reg_insn(val.data.insn_d);
}

static bool has_conflict(struct ir_insn *v1, struct ir_insn *v2)
{
	if (!is_insn_final(v1) || !is_insn_final(v2)) {
		CRITICAL("Can only test conflict on final values");
	}
	if (insn_cg(v1)->nonvr && insn_cg(v2)->nonvr) {
		return false;
	}
	if (v1 == v2) {
		return false;
	}
	if (insn_cg(v1)->nonvr) {
		// R <-> r
		struct array adj = insn_cg(v2)->adj;
		struct ir_insn **pos;
		array_for(pos, adj)
		{
			if (allocated_reg_insn(*pos) ==
			    allocated_reg_insn(v1)) {
				return true;
			}
		}
	} else if (insn_cg(v2)->nonvr) {
		// r <-> R
		struct array adj = insn_cg(v1)->adj;
		struct ir_insn **pos;
		array_for(pos, adj)
		{
			if (allocated_reg_insn(*pos) ==
			    allocated_reg_insn(v2)) {
				return true;
			}
		}
	} else {
		// r <-> r
		bool ok = true;
		struct array adj = insn_cg(v1)->adj;
		struct ir_insn **pos;
		array_for(pos, adj)
		{
			if (allocated_reg_insn(*pos) ==
			    allocated_reg_insn(v2)) {
				ok = false;
				break;
			}
		}
		if (ok) {
			// No conflict!
			return false;
		}
		ok = true;
		adj = insn_cg(v2)->adj;
		array_for(pos, adj)
		{
			if (allocated_reg_insn(*pos) ==
			    allocated_reg_insn(v1)) {
				ok = false;
				break;
			}
		}
		if (ok) {
			// No conflict!
			return false;
		} else {
			// Both have conflict
			return true;
		}
	}
	return false;
}

static void erase_same_reg_assign(struct bpf_ir_env *env,
				  struct ir_function *fun, struct ir_insn *insn)
{
	struct ir_insn *dst_insn = insn_dst(insn);
	struct ir_insn *src_insn = insn->values[0].data.insn_d;
	struct ir_insn_cg_extra *dst_insn_cg = insn_cg(dst_insn);
	struct ir_insn_cg_extra *src_insn_cg = insn_cg(src_insn);
	u8 src_reg = src_insn_cg->alloc_reg;
	u8 dst_reg = dst_insn_cg->alloc_reg;
	DBGASSERT(src_reg == dst_reg);
	// Merge!
	if (dst_insn_cg->nonvr && src_insn_cg->nonvr) {
		// R = R
		bpf_ir_erase_insn_cg(env, fun, insn);
		return;
	}
	if (dst_insn_cg->nonvr) {
		// R = r
		set_insn_dst(env, src_insn, dst_insn);
		bpf_ir_erase_insn_cg(env, fun, insn);
		return;
	}
	// r = R || r = r
	set_insn_dst(env, dst_insn, src_insn);
	bpf_ir_erase_insn_cg(env, fun, insn);
}

/* Optimization: Coalescing

 Returns false if no need to rerun liveness analysis
 */
static bool coalescing(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	// For each BB
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		// For each operation
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			struct ir_insn *insn_dst = insn_dst(insn);
			if (insn->op == IR_INSN_ASSIGN) {
				if (insn->values[0].type == IR_VALUE_INSN) {
					struct ir_insn *src =
						insn->values[0].data.insn_d;
					DBGASSERT(src == insn_dst(src));
					// a = a
					if (insn_cg(src)->alloc_reg ==
					    insn_cg(insn_dst)->alloc_reg) {
						// Remove
						erase_same_reg_assign(env, fun,
								      insn);
						return true;
					}

					// R = R
					if (insn_cg(src)->nonvr &&
					    insn_cg(insn)->nonvr) {
						continue;
					}
					// R = r
					// r = R
					// Able to coalesce

					if (!has_conflict(insn_dst, src)) {
						bool ret = false;
						// No Conflict, could coalesce
						// CRITICAL(
						// 	"Coalescing not implemented");
						// Check if coalescing is beneficial using Briggs' conservative coalescing
						u32 count = 0;
						struct array merged;
						bpf_ir_array_clone(
							env, &merged,
							&insn_cg(src)->adj);
						bpf_ir_array_merge(
							env, &merged,
							&insn_cg(insn_dst)->adj);
						struct ir_insn **pos2;
						array_for(pos2, merged)
						{
							if (*pos2 == insn_dst ||
							    *pos2 == src) {
								continue;
							}
							if (insn_cg((*pos2))
								    ->nonvr &&
							    insn_cg((*pos2))
								    ->spilled) {
								// Pre-colored stack
								continue;
							}
							count++;
						}

						// PRINT_LOG(env, "Count: %u\n", count);
						if (count < BPF_REG_10) {
							// Coalesce
							ret = true;

							PRINT_LOG(
								env,
								"Coalescing %u and %u\n",
								insn_cg(src)
									->alloc_reg,
								insn_cg(insn_dst)
									->alloc_reg);
							if (insn_cg(insn_dst)
								    ->nonvr) {
								// R = r
								set_insn_dst(
									env,
									src,
									insn_dst);
							} else if (insn_cg(src)
									   ->nonvr) {
								// r = R
								set_insn_dst(
									env,
									insn_dst,
									src);
							} else {
								// r = r
								set_insn_dst(
									env,
									insn_dst,
									src);
							}
							// This instruction should have no users
							// bpf_ir_check_no_user(
							// 	env, insn);
							bpf_ir_erase_insn_cg(
								env, fun, insn);
						}
						bpf_ir_array_free(&merged);
						return ret;
					}
				}
			}
		}
	}
	return false;
}

// CG: After init
static void change_ret(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_RET) {
				// ret x
				// ==>
				// R0 = x
				// ret
				struct ir_insn *new_insn =
					bpf_ir_create_assign_insn_cg(
						env, insn, insn->values[0],
						INSERT_FRONT);
				new_insn->alu_op = IR_ALU_64;
				set_insn_dst(env, new_insn,
					     fun->cg_info.regs[0]);
				bpf_ir_val_remove_user(insn->values[0], insn);
				insn->value_num = 0;
			}
		}
	}
}

// After init
static void change_call(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_CALL) {
				for (u8 i = 0; i < insn->value_num; ++i) {
					struct ir_value val = insn->values[i];
					bpf_ir_val_remove_user(val, insn);
					struct ir_insn *new_insn =
						bpf_ir_create_assign_insn_cg(
							env, insn, val,
							INSERT_FRONT);
					set_insn_dst(env, new_insn,
						     fun->cg_info.regs[i + 1]);
				}
				insn->value_num = 0; // Remove all operands
				set_insn_dst(env, insn, fun->cg_info.regs[0]);
			}
		}
	}
}

static int compare_insn(const void *a, const void *b)
{
	struct ir_insn *ap = *(struct ir_insn **)a;
	struct ir_insn *bp = *(struct ir_insn **)b;
	return ap->_insn_id > bp->_insn_id;
}

static void graph_coloring(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Using the Chaitin's Algorithm
	// Using the simple dominance heuristic (Simple traversal of BB)
	tag_ir(fun);
	struct array *all_var = &fun->cg_info.all_var;
	qsort(all_var->data, all_var->num_elem, all_var->elem_size,
	      &compare_insn);
	// all_var is now PEO
	struct ir_insn **pos;
	array_for(pos, (*all_var))
	{
		// Allocate register for *pos
		struct ir_insn *insn = *pos;
		if (insn->op == IR_INSN_REG) {
			CRITICAL(
				"Pre-colored register should not be in all_var");
		}
		struct ir_insn_cg_extra *extra = insn_cg(insn);
		if (extra->allocated) {
			// Already allocated
			continue;
		}
		struct ir_insn **pos2;

		int used_reg[MAX_BPF_REG] = { 0 };
		struct array used_spill;
		INIT_ARRAY(&used_spill, s32);
		array_for(pos2, extra->adj)
		{
			struct ir_insn *insn2 = *pos2; // Adj instruction
			struct ir_insn_cg_extra *extra2 = insn_cg(insn2);
			if (extra2->allocated) {
				if (extra2->spilled) {
					if (extra2->spilled_size == 0) {
						RAISE_ERROR(
							"Found a spilling a register that has 0 size");
					}
					u32 spill_number =
						(extra2->spilled_size - 1) / 8 +
						1;
					for (u32 i = 0; i < spill_number; i++) {
						bpf_ir_array_push_unique(
							env, &used_spill,
							&extra2->spilled -
								i * 8);
					}
				} else {
					used_reg[extra2->alloc_reg] = 1;
				}
			}
		}
		bool need_spill = true;
		for (u8 i = 0; i < BPF_REG_10; i++) { // Wrong!
			if (!used_reg[i]) {
				extra->allocated = true;
				PRINT_LOG(env, "Allocate r%u for %%%zu\n", i,
					  insn->_insn_id);
				extra->alloc_reg = i;
				need_spill = false;
				break;
			}
		}
		if (need_spill) {
			s32 sp = -8;
			while (1) {
				bool found = true;
				s32 *pos3;
				array_for(pos3, used_spill)
				{
					if (*pos3 == sp) {
						sp -= 8;
						found = false;
						break;
					}
				}
				if (found) {
					extra->allocated = true;
					extra->spilled = sp;
					extra->spilled_size =
						8; // Default size for VR
					break;
				}
			}
		}
		bpf_ir_array_free(&used_spill);
	}
}

// Live variable analysis

static void gen_kill(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	// For each BB
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *pos2;
		// For each operation
		list_for_each_entry(pos2, &bb->ir_insn_head, list_ptr) {
			struct ir_insn *insn_dst = insn_dst(pos2);
			struct ir_insn_cg_extra *insn_cg = pos2->user_data;
			if (!bpf_ir_is_void(pos2) && insn_dst) {
				bpf_ir_array_push_unique(env, &insn_cg->kill,
							 &insn_dst);
			}
			struct array value_uses =
				bpf_ir_get_operands(env, pos2);
			struct ir_value **pos3;
			array_for(pos3, value_uses)
			{
				struct ir_value *val = *pos3;
				if (val->type == IR_VALUE_INSN) {
					struct ir_insn *insn = val->data.insn_d;
					DBGASSERT(insn == insn_dst(insn));
					bpf_ir_array_push_unique(
						env, &insn_cg->gen, &insn);
					// array_erase_elem(&insn_cg->kill, insn);
				}
			}
			bpf_ir_array_free(&value_uses);
		}
	}
}

static bool array_contains(struct array *arr, struct ir_insn *insn)
{
	struct ir_insn **pos;
	array_for(pos, (*arr))
	{
		if (*pos == insn) {
			return true;
		}
	}
	return false;
}

static struct array array_delta(struct bpf_ir_env *env, struct array *a,
				struct array *b)
{
	struct array res;
	INIT_ARRAY(&res, struct ir_insn *);
	struct ir_insn **pos;
	array_for(pos, (*a))
	{
		struct ir_insn *insn = *pos;
		if (!array_contains(b, insn)) {
			bpf_ir_array_push(env, &res, &insn);
		}
	}
	return res;
}

static bool equal_set(struct array *a, struct array *b)
{
	if (a->num_elem != b->num_elem) {
		return false;
	}
	struct ir_insn **pos;
	array_for(pos, (*a))
	{
		struct ir_insn *insn = *pos;
		if (!array_contains(b, insn)) {
			return false;
		}
	}
	return true;
}

static void in_out(struct bpf_ir_env *env, struct ir_function *fun)
{
	bool change = true;
	// For each BB
	while (change) {
		change = false;
		struct ir_basic_block **pos;
		array_for(pos, fun->reachable_bbs)
		{
			struct ir_basic_block *bb = *pos;
			struct ir_insn *insn;

			list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
				struct ir_insn_cg_extra *insn_cg =
					insn->user_data;
				struct array old_in = insn_cg->in;
				bpf_ir_array_clear(env, &insn_cg->out);
				CHECK_ERR();

				if (bpf_ir_get_last_insn(bb) == insn) {
					// Last instruction
					struct ir_basic_block **pos2;
					array_for(pos2, bb->succs)
					{
						struct ir_basic_block *bb2 =
							*pos2;
						if (bpf_ir_bb_empty(bb2)) {
							CRITICAL(
								"Found empty BB");
						}
						struct ir_insn *first =
							bpf_ir_get_first_insn(
								bb2);
						struct ir_insn_cg_extra
							*insn2_cg =
								first->user_data;
						bpf_ir_array_merge(
							env, &insn_cg->out,
							&insn2_cg->in);
						CHECK_ERR();
					}
				} else {
					// Not last instruction
					struct ir_insn *next_insn = list_entry(
						insn->list_ptr.next,
						struct ir_insn, list_ptr);
					struct ir_insn_cg_extra *next_insn_cg =
						next_insn->user_data;
					bpf_ir_array_merge(env, &insn_cg->out,
							   &next_insn_cg->in);
					CHECK_ERR();
				}
				struct array out_kill_delta = array_delta(
					env, &insn_cg->out, &insn_cg->kill);
				CHECK_ERR();
				bpf_ir_array_clone(env, &insn_cg->in,
						   &insn_cg->gen);
				CHECK_ERR();
				bpf_ir_array_merge(env, &insn_cg->in,
						   &out_kill_delta);
				CHECK_ERR();
				// Check for change
				if (!equal_set(&insn_cg->in, &old_in)) {
					change = true;
				}
				// Collect garbage
				bpf_ir_array_free(&out_kill_delta);
				bpf_ir_array_free(&old_in);
			}
		}
	}
}

static void print_insn_extra(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_insn_cg_extra *insn_cg = insn->user_data;
	if (insn_cg == NULL) {
		CRITICAL("NULL user data");
	}
	PRINT_LOG(env, "--\nGen:");
	struct ir_insn **pos;
	array_for(pos, insn_cg->gen)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG(env, " ");
		print_insn_ptr_base(env, insn);
	}
	PRINT_LOG(env, "\nKill:");
	array_for(pos, insn_cg->kill)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG(env, " ");
		print_insn_ptr_base(env, insn);
	}
	PRINT_LOG(env, "\nIn:");
	array_for(pos, insn_cg->in)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG(env, " ");
		print_insn_ptr_base(env, insn);
	}
	PRINT_LOG(env, "\nOut:");
	array_for(pos, insn_cg->out)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG(env, " ");
		print_insn_ptr_base(env, insn);
	}
	PRINT_LOG(env, "\n-------------\n");
}

static void liveness_analysis(struct bpf_ir_env *env, struct ir_function *fun)
{
	// TODO: Encode Calling convention into GEN KILL
	gen_kill(env, fun);
	in_out(env, fun);
	if (env->opts.verbose > 2) {
		PRINT_LOG(env, "--------------\n");
		print_ir_prog_advanced(env, fun, NULL, print_insn_extra,
				       print_ir_dst);
		print_ir_prog_advanced(env, fun, NULL, NULL, print_ir_dst);
	}
}

static enum val_type vtype_insn(struct ir_insn *insn)
{
	insn = insn_dst(insn);
	if (insn == NULL) {
		// Void
		return UNDEF;
	}
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	if (extra->spilled) {
		if (insn->op == IR_INSN_ALLOCARRAY) {
			return STACKOFF;
		} else {
			return STACK;
		}
	} else {
		return REG;
	}
}

static enum val_type vtype(struct ir_value val)
{
	if (val.type == IR_VALUE_INSN) {
		return vtype_insn(val.data.insn_d);
	} else if (val.type == IR_VALUE_CONSTANT ||
		   val.type == IR_VALUE_CONSTANT_RAWOFF) {
		return CONST;
	} else {
		CRITICAL("No such value type for dst");
	}
}

/* Test whether an instruction is a VR instruction */
// static bool is_vr_insn(struct ir_insn *insn)
// {
// 	if (insn == NULL || insn->user_data == NULL) {
// 		// Void
// 		return false;
// 	}
// 	return !insn_cg(insn)->nonvr;
// }

/* Test whether a value is a VR instruction */
// static bool is_vr(struct ir_value val)
// {
// 	if (val.type == IR_VALUE_INSN) {
// 		return is_vr_insn(val.data.insn_d);
// 	} else {
// 		return false;
// 	}
// }

// Relocate BB
static void calc_pos(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Calculate the position of each instruction & BB
	size_t ipos = 0; // Instruction position
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_bb_cg_extra *bb_extra = bb->user_data;
		bb_extra->pos = ipos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra *insn_extra = insn_cg(insn);
			for (u8 i = 0; i < insn_extra->translated_num; ++i) {
				struct pre_ir_insn *translated_insn =
					&insn_extra->translated[i];
				// Pos
				translated_insn->pos = ipos;
				if (translated_insn->it == IMM) {
					ipos += 1;
				} else {
					ipos += 2;
				}
			}
		}
	}
	env->insn_cnt = ipos;
}

static void relocate(struct bpf_ir_env *env, struct ir_function *fun)
{
	calc_pos(env, fun);
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra *insn_extra = insn_cg(insn);
			if (insn->op == IR_INSN_JA) {
				DBGASSERT(insn_extra->translated_num == 1);
				size_t target = bpf_ir_bb_cg(insn->bb1)->pos;
				insn_extra->translated[0].off =
					target - insn_extra->translated[0].pos -
					1;
			}
			if (bpf_ir_is_cond_jmp(insn)) {
				DBGASSERT(insn_extra->translated_num == 1);
				size_t target = bpf_ir_bb_cg(insn->bb2)->pos;
				insn_extra->translated[0].off =
					target - insn_extra->translated[0].pos -
					1;
			}
		}
	}
}

// Load a constant (usually 64 bits) to a register
static void cgir_load_const_to_reg(struct bpf_ir_env *env,
				   struct ir_function *fun,
				   struct ir_insn *insn, struct ir_value *val,
				   u8 reg)
{
	struct ir_insn *new_insn =
		bpf_ir_create_assign_insn_cg(env, insn, *val, INSERT_FRONT);
	new_insn->alu_op = IR_ALU_64;
	set_insn_dst(env, new_insn, fun->cg_info.regs[reg]);

	bpf_ir_change_value(env, insn, val,
			    bpf_ir_value_insn(fun->cg_info.regs[reg]));
}

static void cgir_load_reg_to_reg(struct bpf_ir_env *env,
				 struct ir_function *fun, struct ir_insn *insn,
				 struct ir_value *val, u8 reg)
{
	struct ir_insn *new_insn =
		bpf_ir_create_assign_insn_cg(env, insn, *val, INSERT_FRONT);
	new_insn->alu_op = IR_ALU_64;
	set_insn_dst(env, new_insn, fun->cg_info.regs[reg]);
	bpf_ir_change_value(env, insn, val,
			    bpf_ir_value_insn(fun->cg_info.regs[reg]));
}

static void cgir_load_stack_to_reg(struct bpf_ir_env *env,
				   struct ir_function *fun,
				   struct ir_insn *insn, struct ir_value *val,
				   enum ir_vr_type vtype, u8 reg)
{
	struct ir_insn *tmp =
		bpf_ir_create_assign_insn_cg(env, insn, *val, INSERT_FRONT);
	tmp->vr_type = vtype;
	set_insn_dst(env, tmp, fun->cg_info.regs[reg]);

	bpf_ir_change_value(env, insn, val,
			    bpf_ir_value_insn(fun->cg_info.regs[reg]));
}

static void add_stack_offset_vr(struct ir_function *fun, size_t num)
{
	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		if (extra->spilled) {
			extra->spilled -= num * 8;
		}
	}
}

/* Spilling callee

	NOT TESTED YET
 */
static void spill_callee(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Spill Callee saved registers if used
	u8 reg_used[MAX_BPF_REG] = { 0 };

	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		DBGASSERT(extra->allocated);
		if (extra->spilled == 0) {
			reg_used[extra->alloc_reg] = 1;
		}
	}
	size_t off = 0;
	for (u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
		if (reg_used[i]) {
			off++;
		}
	}
	DBGASSERT(off == fun->cg_info.callee_num);
	add_stack_offset_vr(fun, off);
	off = 0;
	for (u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
		// All callee saved registers
		if (reg_used[i]) {
			off++;
			// Spill at sp-off
			// struct ir_insn *st = create_assign_insn_bb_cg(env,
			//     fun->entry, ir_value_insn(fun->cg_info.regs[i]), INSERT_FRONT);
			struct ir_insn *st = bpf_ir_create_insn_base_cg(
				env, fun->entry, IR_INSN_STORERAW);
			bpf_ir_insert_at_bb(st, fun->entry, INSERT_FRONT);
			// st->values[0] = bpf_ir_value_insn(fun->cg_info.regs[i]);
			bpf_ir_val_add_user(env, st->values[0],
					    fun->cg_info.regs[i]);
			st->value_num = 1;
			st->vr_type = IR_VR_TYPE_64;
			st->addr_val.value = bpf_ir_value_stack_ptr(fun);
			st->addr_val.offset = -off * 8;
			set_insn_dst(env, st, NULL);

			struct ir_basic_block **pos2;
			array_for(pos2, fun->end_bbs)
			{
				struct ir_basic_block *bb = *pos2;
				struct ir_insn *ld = bpf_ir_create_insn_base_cg(
					env, bb, IR_INSN_LOADRAW);
				bpf_ir_insert_at_bb(ld, bb,
						    INSERT_BACK_BEFORE_JMP);
				ld->value_num = 0;
				ld->vr_type = IR_VR_TYPE_64;
				// ld->addr_val.value =
				// 	bpf_ir_value_stack_ptr(fun);
				bpf_ir_val_add_user(env, ld->addr_val.value,
						    fun->sp);
				ld->addr_val.offset = -off * 8;

				set_insn_dst(env, ld, fun->cg_info.regs[i]);
			}
		}
	}
}

// Normalization

/* Loading constant used in normalization */
static struct ir_insn *normalize_load_const(struct bpf_ir_env *env,
					    struct ir_insn *insn,
					    struct ir_value *val)
{
	struct ir_insn *new_insn = NULL;
	if (val->const_type == IR_ALU_32) {
		new_insn = bpf_ir_create_assign_insn_cg(env, insn, *val,
							INSERT_FRONT);
		new_insn->alu_op = IR_ALU_64;
	} else {
		new_insn = bpf_ir_create_insn_base_cg(env, insn->parent_bb,
						      IR_INSN_LOADIMM_EXTRA);
		new_insn->imm_extra_type = IR_LOADIMM_IMM64;
		new_insn->imm64 = val->data.constant_d;
		new_insn->vr_type = IR_VR_TYPE_64;
	}
	bpf_ir_change_value(env, insn, val, bpf_ir_value_insn(new_insn));
	return new_insn;
}

static void normalize_assign(struct bpf_ir_env *env, struct ir_function *fun,
			     struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type tdst = vtype_insn(insn);
	struct ir_insn *dst_insn = insn_dst(insn);
	// stack = reg
	// stack = const32
	// reg = const32
	// reg = const64
	// reg = stack
	// reg = reg
	if (tdst == STACK) {
		DBGASSERT(t0 != STACK);
		// Change to STORERAW
		insn->op = IR_INSN_STORERAW;

		bpf_ir_change_value(env, insn, &insn->addr_val.value,
				    bpf_ir_value_stack_ptr(fun));
		insn->addr_val.offset = insn_cg(dst_insn)->spilled;
	} else {
		if (t0 == STACK) {
			// Change to LOADRAW
			insn->op = IR_INSN_LOADRAW;
			bpf_ir_change_value(env, insn, &insn->addr_val.value,
					    bpf_ir_value_stack_ptr(fun));
			insn->addr_val.offset =
				insn_cg(v0->data.insn_d)->spilled;
		}
		if (t0 == CONST && v0->const_type == IR_ALU_64) {
			// 64 imm load
			insn->op = IR_INSN_LOADIMM_EXTRA;
			insn->imm_extra_type = IR_LOADIMM_IMM64;
			insn->imm64 = v0->data.constant_d;
		}
	}
	if (tdst == REG && t0 == REG) {
		if (allocated_reg_insn(dst_insn) == allocated_reg(*v0)) {
			// The same, erase this instruction
			erase_same_reg_assign(env, fun, insn);
		}
	}
}

/* Normalize ALU */
static void normalize_alu(struct bpf_ir_env *env, struct ir_function *fun,
			  struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) : UNDEF;
	enum val_type tdst = vtype_insn(insn);
	struct ir_insn *dst_insn = insn_dst(insn);
	DBGASSERT(tdst == REG);
	if (t1 == REG) {
		// tdst != t1
		DBGASSERT(allocated_reg_insn(dst_insn) != allocated_reg(*v1));
	}
	if (t0 == CONST) {
		DBGASSERT(v0->const_type == IR_ALU_32);
	}
	if (t1 == CONST) {
		DBGASSERT(v1->const_type == IR_ALU_32);
	}
	// Binary ALU
	if (t0 == STACK && t1 == CONST) {
		// reg1 = add stack const
		// ==>
		// reg1 = stack
		// reg1 = add reg1 const
		struct ir_insn *new_insn = bpf_ir_create_assign_insn_cg(
			env, insn, *v0, INSERT_FRONT);
		new_insn->vr_type = IR_VR_TYPE_64;
		set_insn_dst(env, new_insn, dst_insn);
		bpf_ir_change_value(env, insn, v0, bpf_ir_value_insn(dst_insn));
		normalize_assign(env, fun, new_insn);
	} else if (t0 == STACK && t1 == REG) {
		// reg1 = add stack reg2
		// ==>
		// reg1 = stack
		// reg1 = add reg1 reg2
		struct ir_insn *new_insn = bpf_ir_create_assign_insn_cg(
			env, insn, *v0, INSERT_FRONT);
		set_insn_dst(env, new_insn, dst_insn);
		new_insn->vr_type = IR_VR_TYPE_64;
		bpf_ir_change_value(env, insn, v0, bpf_ir_value_insn(dst_insn));
		normalize_assign(env, fun, new_insn);
	} else if (t0 == REG && t1 == REG) {
		// reg1 = add reg2 reg3
		u8 reg1 = insn_cg(dst_insn)->alloc_reg;
		u8 reg2 = insn_cg(v0->data.insn_d)->alloc_reg;
		if (reg1 != reg2) {
			// reg1 = add reg2 reg3
			// ==>
			// reg1 = reg2
			// reg1 = add reg1 reg3
			struct ir_insn *new_insn = bpf_ir_create_assign_insn_cg(
				env, insn, *v0, INSERT_FRONT);
			DBGASSERT(dst_insn == fun->cg_info.regs[reg1]);
			set_insn_dst(env, new_insn, dst_insn);
			bpf_ir_change_value(env, insn, v0,
					    bpf_ir_value_insn(dst_insn));
		}
	} else if (t0 == REG && t1 == CONST) {
		if (allocated_reg(*v0) != allocated_reg_insn(dst_insn)) {
			// reg1 = add reg2 const
			// ==>
			// reg1 = reg2
			// reg1 = add reg1 const
			struct ir_insn *new_insn = bpf_ir_create_assign_insn_cg(
				env, insn, *v0, INSERT_FRONT);
			set_insn_dst(env, new_insn, dst_insn);
			bpf_ir_change_value(env, insn, v0,
					    bpf_ir_value_insn(dst_insn));
		}
	} else if (t0 == CONST && t1 == CONST) {
		DBGASSERT(v1->const_type == IR_ALU_32);
		struct ir_insn *load_const_insn =
			normalize_load_const(env, insn, v0);
		set_insn_dst(env, load_const_insn, dst_insn);
	} else if (t0 == CONST && t1 == REG) {
		// reg1 = add const reg2
		// ==>
		// reg1 = const
		// reg1 = add reg1 reg2
		struct ir_insn *load_const_insn =
			normalize_load_const(env, insn, v0);
		set_insn_dst(env, load_const_insn, dst_insn);

	} else {
		CRITICAL_DUMP(env, "Error");
	}
}

static void normalize_getelemptr(struct bpf_ir_env *env,
				 struct ir_function *fun, struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) : UNDEF;
	enum val_type tdst = vtype_insn(insn);
	struct ir_insn *dst_insn = insn_dst(insn);
	DBGASSERT(tdst == REG);
	DBGASSERT(t1 == STACKOFF);
	DBGASSERT(v1->type == IR_VALUE_INSN &&
		  v1->data.insn_d->op == IR_INSN_ALLOCARRAY);
	struct ir_insn_cg_extra *v1_extra = insn_cg(v1->data.insn_d);
	s32 spill_pos = v1_extra->spilled;
	insn->op = IR_INSN_ADD;
	insn->alu_op = IR_ALU_64;
	if (t0 == CONST) {
		// reg = getelemptr const ptr
		// ==>
		// reg = r10 + (const + spill_pos)
		DBGASSERT(v0->const_type == IR_ALU_32);
		s64 tmp = v0->data.constant_d + spill_pos; // Assume no overflow
		bpf_ir_change_value(env, insn, v0, bpf_ir_value_insn(fun->sp));
		bpf_ir_change_value(env, insn, v1, bpf_ir_value_const32(tmp));
		normalize_alu(env, fun, insn);
	}
	if (t0 == REG) {
		bpf_ir_change_value(env, insn, v1,
				    bpf_ir_value_const32(spill_pos));
		if (allocated_reg(*v0) == allocated_reg_insn(dst_insn)) {
			// reg = getelemptr reg ptr
			// ==>
			// reg += r10
			// reg += spill_pos
			bpf_ir_change_value(env, insn, v0,
					    bpf_ir_value_insn(dst_insn));
			struct ir_insn *new_insn = bpf_ir_create_bin_insn_cg(
				env, insn, bpf_ir_value_insn(dst_insn),
				bpf_ir_value_insn(fun->sp), IR_INSN_ADD,
				IR_ALU_64, INSERT_FRONT);
			set_insn_dst(env, new_insn, dst_insn);
		} else {
			// reg1 = getelemptr reg2 ptr
			// ==>
			// reg1 = reg2
			// reg1 += r10
			// reg1 += spill_pos
			struct ir_insn *assign_insn =
				bpf_ir_create_assign_insn_cg(env, insn, *v0,
							     INSERT_FRONT);
			set_insn_dst(env, assign_insn, dst_insn);
			struct ir_insn *alu_insn = bpf_ir_create_bin_insn_cg(
				env, insn, bpf_ir_value_insn(dst_insn),
				bpf_ir_value_insn(fun->sp), IR_INSN_ADD,
				IR_ALU_64, INSERT_FRONT);
			set_insn_dst(env, alu_insn, dst_insn);
			bpf_ir_change_value(env, insn, v0,
					    bpf_ir_value_insn(dst_insn));
		}
	}
}

static void normalize_stackoff(struct bpf_ir_env *env, struct ir_function *fun,
			       struct ir_insn *insn)
{
	// Stack already shifted
	struct ir_value addrval = insn->addr_val.value;
	enum val_type addr_ty = vtype(addrval);
	// storeraw STACKOFF ?
	// ==>
	// storeraw r10 ?
	if (addr_ty == STACKOFF) {
		insn->addr_val.offset += insn_cg(addrval.data.insn_d)->spilled;
		bpf_ir_change_value(env, insn, &insn->addr_val.value,
				    bpf_ir_value_stack_ptr(fun));
	}
}

static void normalize(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (insn->op == IR_INSN_ALLOC) {
				// OK
			} else if (insn->op == IR_INSN_ALLOCARRAY) {
				// OK
			} else if (insn->op == IR_INSN_GETELEMPTR) {
				normalize_getelemptr(env, fun, insn);
			} else if (insn->op == IR_INSN_STORE) {
				// Should be converted to ASSIGN
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOAD) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOADRAW) {
				normalize_stackoff(env, fun, insn);
			} else if (insn->op == IR_INSN_LOADIMM_EXTRA) {
				// OK
			} else if (insn->op == IR_INSN_STORERAW) {
				normalize_stackoff(env, fun, insn);
			} else if (bpf_ir_is_alu(insn)) {
				normalize_alu(env, fun, insn);
			} else if (insn->op == IR_INSN_ASSIGN) {
				normalize_assign(env, fun, insn);
			} else if (insn->op == IR_INSN_RET) {
				// OK
			} else if (insn->op == IR_INSN_CALL) {
				// OK
			} else if (insn->op == IR_INSN_JA) {
				// OK
			} else if (bpf_ir_is_cond_jmp(insn)) {
				// jmp reg const/reg
				// or
				// jmp const/reg reg
				// OK
			} else {
				RAISE_ERROR("No such instruction");
			}
		}
	}
}

/* Spill ASSIGN instruction */
static bool spill_assign(struct bpf_ir_env *env, struct ir_function *fun,
			 struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type tdst = vtype_insn(insn);

	// `dst = src`

	// Cases of `dst, src`:

	// - `STACK, STACK`
	// - `STACK, REG`
	// - `STACK, CONST`
	// - `REG, CONST`
	// - `REG, REG`
	// - `REG, STACK`

	// Possible result:

	// REG = REG
	// REG = CONST
	// REG = STACK
	// STACK = REG
	// STACK = CONST32

	if (tdst == STACK && t0 == STACK) {
		// Both stack positions are managed by us
		cgir_load_stack_to_reg(env, fun, insn, v0, IR_VR_TYPE_64, 0);
		return true;
	}
	if (tdst == STACK && t0 == CONST) {
		if (v0->const_type == IR_ALU_64) {
			// First load to R0
			cgir_load_const_to_reg(env, fun, insn, v0, 0);
			return true;
		}
	}
	return false;
}

/* Spill STORE instructions */
static bool spill_store(struct bpf_ir_env *env, struct ir_function *fun,
			struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	// store v0(dst) v1
	// Equivalent to `v0 = v1`
	insn->op = IR_INSN_ASSIGN;
	DBGASSERT(v0->type ==
		  IR_VALUE_INSN); // Should be guaranteed by prog_check
	DBGASSERT(v0->data.insn_d->op == IR_INSN_ALLOC);
	insn->vr_type = v0->data.insn_d->vr_type;
	DBGASSERT(insn_cg(insn)->dst.type == IR_VALUE_UNDEF);
	DBGASSERT(insn->users.num_elem == 0); // Store has no users
	bpf_ir_val_remove_user(*v0, insn);
	set_insn_dst(env, insn, v0->data.insn_d);
	insn->value_num = 1;
	*v0 = *v1;
	spill_assign(env, fun, insn);
	return true;
}

static bool spill_load(struct bpf_ir_env *env, struct ir_function *fun,
		       struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	// stack = load stack
	// stack = load reg
	// reg = load reg
	// reg = load stack
	insn->op = IR_INSN_ASSIGN;
	DBGASSERT(v0->type ==
		  IR_VALUE_INSN); // Should be guaranteed by prog_check
	DBGASSERT(v0->data.insn_d->op == IR_INSN_ALLOC);
	insn->vr_type = v0->data.insn_d->vr_type;
	spill_assign(env, fun, insn);
	return true;
}

static bool spill_loadraw(struct bpf_ir_env *env, struct ir_function *fun,
			  struct ir_insn *insn)
{
	enum val_type tdst = vtype_insn(insn);
	enum val_type t0 = vtype(insn->addr_val.value);
	// struct ir_insn *dst_insn = insn_dst(insn);
	// Load from memory
	// reg = loadraw reg ==> OK
	// reg = loadraw const ==> TODO
	if (t0 == CONST) {
		CRITICAL("Not supported");
	}

	if (tdst == STACK) {
		if (t0 == REG) {
			// stack = loadraw reg
			// ==>
			// R0 = loadraw reg
			// stack = R0
			struct ir_insn *new_insn =
				bpf_ir_create_loadraw_insn_cg(env, insn,
							      insn->vr_type,
							      insn->addr_val,
							      INSERT_FRONT);
			set_insn_dst(env, new_insn, fun->cg_info.regs[0]);
			insn->value_num = 1;
			insn->op = IR_INSN_ASSIGN;
			insn->vr_type = IR_VR_TYPE_64;
			bpf_ir_val_remove_user(insn->addr_val.value, insn);
			insn->values[0] =
				bpf_ir_value_insn(fun->cg_info.regs[0]);
			bpf_ir_val_add_user(env, insn->values[0], insn);
			return true;
		}
		if (t0 == STACK) {
			// stack = loadraw stack
			// ==>
			// R0 = loadraw stack
			// stack = R0

			struct ir_insn *new_insn =
				bpf_ir_create_loadraw_insn_cg(env, insn,
							      insn->vr_type,
							      insn->addr_val,
							      INSERT_FRONT);
			set_insn_dst(env, new_insn, fun->cg_info.regs[0]);
			insn->value_num = 1;
			insn->op = IR_INSN_ASSIGN;
			bpf_ir_val_remove_user(insn->addr_val.value, insn);
			insn->values[0] =
				bpf_ir_value_insn(fun->cg_info.regs[0]);
			bpf_ir_val_add_user(env, insn->values[0], insn);
			insn->vr_type = IR_VR_TYPE_64;

			cgir_load_stack_to_reg(env, fun, new_insn,
					       &new_insn->addr_val.value,
					       IR_VR_TYPE_64, 0);
			return true;
		}
	}
	if (tdst == REG && t0 == STACK) {
		cgir_load_stack_to_reg(env, fun, insn, &insn->addr_val.value,
				       IR_VR_TYPE_64, 0);
		return true;
	}
	return false;
}

static bool spill_loadrawextra(struct bpf_ir_env *env, struct ir_function *fun,
			       struct ir_insn *insn)
{
	enum val_type tdst = vtype_insn(insn);
	// struct ir_insn *dst_insn = insn_dst(insn);
	// IMM64 Map instructions, must load to register
	if (tdst == STACK) {
		// stack = loadimm
		// ==>
		// R0 = loadimm
		// stack = R0
		struct ir_insn *new_insn = bpf_ir_create_loadimmextra_insn_cg(
			env, insn, insn->imm_extra_type, insn->imm64,
			INSERT_FRONT);
		set_insn_dst(env, new_insn, fun->cg_info.regs[0]);

		insn->op = IR_INSN_ASSIGN;
		insn->value_num = 1;
		insn->values[0] = bpf_ir_value_insn(fun->cg_info.regs[0]);
		bpf_ir_val_add_user(env, insn->values[0], insn);
		insn->vr_type = IR_VR_TYPE_64;
		return true;
	}
	return false;
}

static bool spill_storeraw(struct bpf_ir_env *env, struct ir_function *fun,
			   struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	// Store some value to memory
	// store ptr reg ==> OK
	// store ptr stack

	// store stackptr stack
	// ==> TODO!
	enum val_type addr_ty = vtype(insn->addr_val.value);
	if (addr_ty == CONST) {
		CRITICAL("Not supported");
	}
	if (addr_ty == STACK) {
		CRITICAL("TODO!");
	}
	DBGASSERT(addr_ty == REG);
	if (t0 == CONST && v0->const_type == IR_ALU_64) {
		// store ptr const64
		// ==>
		// r' = const64
		// store ptr r'
		u8 reg = 0;
		if (addr_ty == REG &&
		    insn_cg(insn->addr_val.value.data.insn_d)->alloc_reg == 0) {
			// Make sure the new register is not the same as the other register
			reg = 1;
		}
		cgir_load_const_to_reg(env, fun, insn, v0, reg);
		return true;
	}
	// Question: are all memory address 64 bits?
	if (t0 == STACK) {
		u8 reg = 0;
		if (addr_ty == REG &&
		    insn_cg(insn->addr_val.value.data.insn_d)->alloc_reg == 0) {
			// Make sure the new register is not the same as the other register
			reg = 1;
		}
		cgir_load_stack_to_reg(env, fun, insn, v0, IR_VR_TYPE_64, reg);
		return true;
	}
	return false;
}

static bool spill_alu(struct bpf_ir_env *env, struct ir_function *fun,
		      struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) : UNDEF;
	enum val_type tdst = vtype_insn(insn);
	struct ir_insn *dst_insn = insn_dst(insn);
	// Binary ALU
	// reg = ALU reg reg
	// reg = ALU reg const
	// There should be NO stack
	if (tdst == STACK) {
		// stack = ALU ? ?
		// ==>
		// R0 = ALU ? ?
		// stack = R0
		// Note: We should keep the tdst as stack, only change the insn type
		struct ir_insn *new_alu =
			bpf_ir_create_bin_insn_cg(env, insn, *v0, *v1, insn->op,
						  insn->alu_op, INSERT_FRONT);
		set_insn_dst(env, new_alu, fun->cg_info.regs[0]);
		bpf_ir_val_remove_user(*v1, insn);
		insn->op = IR_INSN_ASSIGN;
		insn->value_num = 1;
		bpf_ir_change_value(env, insn, v0,
				    bpf_ir_value_insn(fun->cg_info.regs[0]));
		insn->vr_type = IR_VR_TYPE_64;
		spill_alu(env, fun, new_alu);
		return true;
	}

	if (t1 == REG && allocated_reg_insn(dst_insn) == allocated_reg(*v1)) {
		// r0 = ALU ? r0
		// ==>
		// R1 = r0
		// r0 = ALU ? R1
		u8 new_reg = allocated_reg_insn(dst_insn) == 0 ? 1 : 0;
		cgir_load_reg_to_reg(env, fun, insn, v1, new_reg);
		spill_alu(env, fun, insn);
		return true;
	}
	if (t0 == REG) {
		if (t1 == CONST) {
			// reg = ALU reg const
			if (v1->const_type == IR_ALU_64) {
				// reg = ALU reg const64
				u8 new_reg = allocated_reg(*v0) == 0 ? 1 : 0;
				cgir_load_const_to_reg(env, fun, insn, v1,
						       new_reg);
				spill_alu(env, fun, insn);
				return true;
			} else if (v1->const_type == IR_ALU_32) {
				// PASS
			} else {
				CRITICAL("No such const type");
			}
		}

		if (t1 == STACK) {
			// reg = ALU reg stack
			// reg = ALU reg const64
			u8 new_reg = allocated_reg(*v0) == 0 ? 1 : 0;
			cgir_load_stack_to_reg(env, fun, insn, v1,
					       IR_VR_TYPE_64, new_reg);
			spill_alu(env, fun, insn);
			return true;
		}
	} else {
		// Convert t0 to REG
		if (t0 == STACK) {
			// reg = ALU stack ?
			if (t1 == CONST && v1->const_type == IR_ALU_32) {
				// reg = ALU stack const32
				// PASS
				return false;
			}
			if (t1 == REG) {
				// reg = ALU stack reg2
				// PASS
				return false;
			}
			u8 new_reg = 0;
			if (t1 == REG && allocated_reg(*v1) == 0) {
				new_reg = 1;
			}
			cgir_load_stack_to_reg(env, fun, insn, v0,
					       IR_VR_TYPE_64, new_reg);
			spill_alu(env, fun, insn);
			return true;
		}
		if (t0 == CONST) {
			if (v0->const_type == IR_ALU_64) {
				if (t1 == CONST &&
				    v1->const_type == IR_ALU_32) {
					// PASS
					return false;
				}
				u8 new_reg = 0;
				if (t1 == REG && allocated_reg(*v1) == 0) {
					new_reg = 1;
				}
				cgir_load_const_to_reg(env, fun, insn, v0,
						       new_reg);
				spill_alu(env, fun, insn);
				return true;
			} else if (v0->const_type == IR_ALU_32) {
				if (t1 == CONST &&
				    v1->const_type == IR_ALU_64) {
					// reg = ALU const32 const64
					cgir_load_const_to_reg(env, fun, insn,
							       v1, 0);
					spill_alu(env, fun, insn);
					return true;
				}
				if (t1 == STACK) {
					// reg = ALU const32 stack
					cgir_load_stack_to_reg(env, fun, insn,
							       v1,
							       IR_VR_TYPE_64,
							       0);
					spill_alu(env, fun, insn);
					return true;
				}
			} else {
				CRITICAL("IMPOSSIBLE ALU TYPE");
			}
		}
	}

	return false;
}

static bool spill_cond_jump(struct bpf_ir_env *env, struct ir_function *fun,
			    struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) : UNDEF;
	if (t0 == REG) {
		// jmp reg ?
		u8 reg = 0;
		if (allocated_reg(*v0) == 0) {
			reg = 1;
		}
		if (t1 == STACK) {
			cgir_load_stack_to_reg(env, fun, insn, v1,
					       IR_VR_TYPE_64, reg);
			return true;
		}
		if (t1 == CONST && v1->const_type == IR_ALU_64) {
			cgir_load_const_to_reg(env, fun, insn, v1, reg);
			return true;
		}
	} else {
		u8 reg = 0;
		if (t1 == REG && allocated_reg(*v1) == 0) {
			reg = 1;
		}
		if (t0 == STACK) {
			// First change t0 to REG
			cgir_load_stack_to_reg(env, fun, insn, v0,
					       IR_VR_TYPE_64, reg);
			spill_cond_jump(env, fun, insn);
			return true;
		} else {
			// CONST
			PRINT_LOG(
				env,
				"Warning: using const as the first operand of conditional jump may impact performance.");

			cgir_load_const_to_reg(env, fun, insn, v0, reg);
			spill_cond_jump(env, fun, insn);
			return true;
		}
	}
	return false;
}

static bool spill_getelemptr(struct bpf_ir_env *env, struct ir_function *fun,
			     struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) : UNDEF;
	enum val_type tdst = vtype_insn(insn);
	// struct ir_insn *dst_insn = insn_dst(insn);
	ASSERT_DUMP(v1->type == IR_VALUE_INSN, false);
	ASSERT_DUMP(v1->data.insn_d->op == IR_INSN_ALLOCARRAY, false);
	ASSERT_DUMP(t1 == STACKOFF, false);
	if (tdst == STACK) {
		// stack = getelemptr reg ptr
		// ==>
		// R0 = getelemptr reg ptr
		// stack = R0

		struct ir_insn *new_insn = bpf_ir_create_getelemptr_insn_cg(
			env, insn, v1->data.insn_d, *v0, INSERT_FRONT);
		bpf_ir_val_remove_user(*v1, insn);

		bpf_ir_change_value(env, insn, v0,
				    bpf_ir_value_insn(fun->cg_info.regs[0]));
		insn->value_num = 1;
		insn->op = IR_INSN_ASSIGN;
		set_insn_dst(env, new_insn, fun->cg_info.regs[0]);
		spill_getelemptr(env, fun, insn);
		return true;
	}
	if (t0 == STACK) {
		cgir_load_stack_to_reg(env, fun, insn, v0, IR_VR_TYPE_64, 0);
		return true;
	}
	if (t0 == CONST && v0->const_type == IR_ALU_64) {
		cgir_load_const_to_reg(env, fun, insn, v0, 0);
		return true;
	}
	return false;
}

static void check_insn_users_use_insn_cg(struct bpf_ir_env *env,
					 struct ir_insn *insn)
{
	struct ir_insn **pos;
	array_for(pos, insn->users)
	{
		struct ir_insn *user = *pos;
		// Check if the user actually uses this instruction
		struct array operands = bpf_ir_get_operands_and_dst(env, user);
		struct ir_value **val;
		int found = 0;
		array_for(val, operands)
		{
			struct ir_value *v = *val;
			if (v->type == IR_VALUE_INSN &&
			    v->data.insn_d == insn) {
				// Found the user
				found = 1;
				break;
			}
		}
		bpf_ir_array_free(&operands);
		if (!found) {
			// Error!
			if (!insn_cg(insn)->nonvr) {
				print_ir_insn_err_full(env, insn,
						       "The instruction",
						       print_ir_dst);
			} else {
				PRINT_LOG(env, "The instruction is non-vr.\n");
			}
			print_ir_insn_err_full(env, user,
					       "The user of that instruction",
					       print_ir_dst);
			RAISE_ERROR("User does not use the instruction");
		}
	}
}

static void check_insn_operand_cg(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct array operands = bpf_ir_get_operands_and_dst(env, insn);
	struct ir_value **val;
	array_for(val, operands)
	{
		struct ir_value *v = *val;
		if (v->type == IR_VALUE_INSN) {
			// Check if the operand actually is used by this instruction
			struct ir_insn **pos2;
			int found = 0;
			array_for(pos2, v->data.insn_d->users)
			{
				struct ir_insn *user = *pos2;
				if (user == insn) {
					// Found the user
					found = 1;
					break;
				}
			}
			if (!found) {
				// Error!
				print_ir_insn_err_full(env, v->data.insn_d,
						       "Operand defined here",
						       print_ir_dst);
				print_ir_insn_err_full(
					env, insn,
					"Instruction that uses the operand",
					print_ir_dst);
				RAISE_ERROR(
					"Instruction not found in the operand's users");
			}

			// Check dst

			struct ir_insn *dst_insn = v->data.insn_d;
			if (insn_dst(dst_insn) == NULL) {
				print_ir_insn_err_full(env, dst_insn,
						       "Operand's dst is NULL",
						       print_ir_dst);
				print_ir_insn_err_full(
					env, insn,
					"This instruction's operand's dst is NULL",
					print_ir_dst);
				RAISE_ERROR("NULL dst");
			}
			if (insn_dst(dst_insn) != dst_insn) {
				print_ir_insn_err_full(env, insn_dst(dst_insn),
						       "Operand's dst",
						       print_ir_dst);
				print_ir_insn_err_full(env, dst_insn, "Operand",
						       print_ir_dst);
				print_ir_insn_err_full(
					env, insn,
					"This instruction's operand's dst is NULL",
					print_ir_dst);
				RAISE_ERROR("NULL dst");
			}
		}
	}
	bpf_ir_array_free(&operands);
}

static void prog_check_cg(struct bpf_ir_env *env, struct ir_function *fun)
{
	// CG IR check
	// Available to run while dst is maintained

	print_ir_err_init(fun);

	check_insn_users_use_insn_cg(env, fun->sp);
	for (u8 i = 0; i < BPF_REG_10; ++i) {
		check_insn_users_use_insn_cg(env, fun->cg_info.regs[i]);
	}
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			// Check dst
			if (insn->op == IR_INSN_PHI) {
				print_ir_insn_err_full(env, insn,
						       "Phi instruction",
						       print_ir_dst);
				RAISE_ERROR("Phi instruction found during CG");
			}
			if (insn_cg(insn)->dst.type == IR_VALUE_INSN) {
				// Check users of this instruction
				check_insn_users_use_insn_cg(env, insn);
			} else {
				if (insn_cg(insn)->dst.type != IR_VALUE_UNDEF) {
					print_ir_insn_err_full(env, insn,
							       "Instruction",
							       print_ir_dst);
					RAISE_ERROR(
						"Instruction's dst is incorrect value");
				}
				// dst == NULL
				// There should be no users!
				if (insn->users.num_elem > 0) {
					print_ir_insn_err_full(env, insn,
							       "Instruction",
							       print_ir_dst);
					RAISE_ERROR(
						"NULL dst Instruction has users");
				}
			}
			// Check operands of this instruction
			check_insn_operand_cg(env, insn);
		}
	}
}

static bool check_need_spill(struct bpf_ir_env *env, struct ir_function *fun)
{
	bool need_modify = false; // Need to modify the IR
	// Check if all instruction values are OK for translating
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (insn->op == IR_INSN_ALLOC) {
				// dst = alloc <size>
				// Nothing to do
			} else if (insn->op == IR_INSN_ALLOCARRAY) {
				// Nothing to do
			} else if (insn->op == IR_INSN_GETELEMPTR) {
				need_modify |= spill_getelemptr(env, fun, insn);
			} else if (insn->op == IR_INSN_STORE) {
				need_modify |= spill_store(env, fun, insn);
			} else if (insn->op == IR_INSN_LOAD) {
				need_modify |= spill_load(env, fun, insn);
			} else if (insn->op == IR_INSN_LOADRAW) {
				need_modify |= spill_loadraw(env, fun, insn);
			} else if (insn->op == IR_INSN_LOADIMM_EXTRA) {
				need_modify |=
					spill_loadrawextra(env, fun, insn);
			} else if (insn->op == IR_INSN_STORERAW) {
				need_modify |= spill_storeraw(env, fun, insn);
			} else if (bpf_ir_is_alu(insn)) {
				need_modify |= spill_alu(env, fun, insn);
			} else if (insn->op == IR_INSN_ASSIGN) {
				need_modify |= spill_assign(env, fun, insn);
			} else if (insn->op == IR_INSN_RET) {
				// ret const/reg
				// Done in explicit_reg pass
				DBGASSERT(insn->value_num == 0);
			} else if (insn->op == IR_INSN_CALL) {
				// call()
				// Should have no arguments
				DBGASSERT(insn->value_num == 0);
			} else if (insn->op == IR_INSN_JA) {
				// OK
			} else if (bpf_ir_is_cond_jmp(insn)) {
				need_modify |= spill_cond_jump(env, fun, insn);
			} else {
				RAISE_ERROR_RET("No such instruction", false);
			}
			CHECK_ERR(false);
		}
	}
	return need_modify;
}

static void calc_callee_num(struct ir_function *fun)
{
	u8 reg_used[MAX_BPF_REG] = { 0 };

	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		reg_used[extra->alloc_reg] = 1;
	}
	size_t off = 0;
	for (u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
		if (reg_used[i]) {
			off++;
		}
	}
	fun->cg_info.callee_num = off;
}

static void calc_stack_size(struct ir_function *fun)
{
	// Check callee
	s32 off = 0;
	if (fun->cg_info.spill_callee) {
		off -= fun->cg_info.callee_num * 8;
	}
	// Check all VR
	s32 max = 0;
	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		if (extra->spilled) {
			// Spilled!
			if (extra->spilled < max) {
				max = extra->spilled;
			}
		}
	}
	fun->cg_info.stack_offset = off + max;
	PRINT_DBG("Stack size: %d\n", fun->cg_info.stack_offset);
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
				if (insn->addr_val.value.type ==
					    IR_VALUE_INSN &&
				    insn->addr_val.value.data.insn_d ==
					    fun->sp) {
					insn->addr_val.offset += offset;
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
				}
			}
			bpf_ir_array_free(&value_uses);
		}
	}
}

static struct pre_ir_insn translate_reg_to_reg(u8 dst, u8 src)
{
	// MOV dst src
	struct pre_ir_insn insn = { 0 };
	insn.opcode = BPF_MOV | BPF_X | BPF_ALU64;
	insn.dst_reg = dst;
	insn.src_reg = src;
	insn.imm = 0;
	return insn;
}

static struct pre_ir_insn translate_const_to_reg(u8 dst, s64 data,
						 enum ir_alu_op_type type)
{
	// MOV dst imm
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	if (type == IR_ALU_32) {
		insn.opcode = BPF_MOV | BPF_K | BPF_ALU;
	} else {
		// Default is imm64
		insn.opcode = BPF_MOV | BPF_K | BPF_ALU64;
	}
	insn.imm = data;
	return insn;
}

static int vr_type_to_size(enum ir_vr_type type)
{
	switch (type) {
	case IR_VR_TYPE_32:
		return BPF_W;
	case IR_VR_TYPE_16:
		return BPF_H;
	case IR_VR_TYPE_8:
		return BPF_B;
	case IR_VR_TYPE_64:
		return BPF_DW;
	default:
		CRITICAL("Error");
	}
}

static struct pre_ir_insn load_addr_to_reg(u8 dst, struct ir_address_value addr,
					   enum ir_vr_type type)
{
	// MOV dst src
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	insn.off = addr.offset;
	int size = vr_type_to_size(type);
	if (addr.value.type == IR_VALUE_INSN) {
		// Must be REG
		DBGASSERT(vtype(addr.value) == REG);
		// Load reg (addr) to reg
		insn.src_reg = insn_cg(addr.value.data.insn_d)->alloc_reg;
		insn.opcode = BPF_LDX | size | BPF_MEM;
	} else if (addr.value.type == IR_VALUE_CONSTANT) {
		// Must be U64
		insn.it = IMM64;
		insn.imm64 = addr.value.data.constant_d;
		insn.opcode = size;
		// Simplify the opcode to reduce compiler warning, the real opcode is as follows
		// (but BPF_MM and BPF_LD are all 0)
		// insn.opcode = BPF_IMM | size | BPF_LD;
	} else {
		CRITICAL("Error");
	}
	return insn;
}

static struct pre_ir_insn store_reg_to_reg_mem(u8 dst, u8 src, s16 offset,
					       enum ir_vr_type type)
{
	struct pre_ir_insn insn = { 0 };
	int size = vr_type_to_size(type);
	insn.src_reg = src;
	insn.off = offset;
	insn.opcode = BPF_STX | size | BPF_MEM;
	insn.dst_reg = dst;
	return insn;
}

static struct pre_ir_insn store_const_to_reg_mem(u8 dst, s64 val, s16 offset,
						 enum ir_vr_type type)
{
	struct pre_ir_insn insn = { 0 };
	int size = vr_type_to_size(type);
	insn.it = IMM;
	insn.imm = val;
	insn.off = offset;
	insn.opcode = BPF_ST | size | BPF_MEM;
	insn.dst_reg = dst;
	return insn;
}

static int alu_code(enum ir_insn_type insn)
{
	switch (insn) {
	case IR_INSN_ADD:
		return BPF_ADD;
	case IR_INSN_SUB:
		return BPF_SUB;
	case IR_INSN_MUL:
		return BPF_MUL;
	case IR_INSN_MOD:
		return BPF_MOD;
	case IR_INSN_LSH:
		return BPF_LSH;
	default:
		CRITICAL("Error");
	}
}

static int jmp_code(enum ir_insn_type insn)
{
	switch (insn) {
	case IR_INSN_JA:
		return BPF_JA;
	case IR_INSN_JEQ:
		return BPF_JEQ;
	case IR_INSN_JNE:
		return BPF_JNE;
	case IR_INSN_JLT:
		return BPF_JLT;
	case IR_INSN_JLE:
		return BPF_JLE;
	case IR_INSN_JGT:
		return BPF_JGT;
	case IR_INSN_JGE:
		return BPF_JGE;
	case IR_INSN_JSGT:
		return BPF_JSGT;
	case IR_INSN_JSLT:
		return BPF_JSLT;
	default:
		CRITICAL("Error");
	}
}

static struct pre_ir_insn alu_reg(u8 dst, u8 src, enum ir_alu_op_type type,
				  int opcode)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	insn.src_reg = src;
	int alu_class = type == IR_ALU_64 ? BPF_ALU64 : BPF_ALU;
	insn.opcode = opcode | BPF_X | alu_class;
	return insn;
}

static struct pre_ir_insn alu_imm(u8 dst, s64 src, enum ir_alu_op_type type,
				  int opcode)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	int alu_class = type == IR_ALU_64 ? BPF_ALU64 : BPF_ALU;
	insn.it = IMM;
	insn.imm = src;
	insn.opcode = opcode | BPF_K | alu_class;
	return insn;
}

static struct pre_ir_insn cond_jmp_reg(u8 dst, u8 src, enum ir_alu_op_type type,
				       int opcode)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	insn.src_reg = src;
	int alu_class = type == IR_ALU_64 ? BPF_JMP : BPF_JMP32;
	insn.opcode = opcode | alu_class | BPF_X;
	return insn;
}

static struct pre_ir_insn cond_jmp_imm(u8 dst, s64 src,
				       enum ir_alu_op_type type, int opcode)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	int alu_class = type == IR_ALU_64 ? BPF_JMP : BPF_JMP32;
	insn.it = IMM;
	insn.imm = src;
	insn.opcode = opcode | alu_class | BPF_K;
	return insn;
}

static u8 get_alloc_reg(struct ir_insn *insn)
{
	return insn_cg(insn)->alloc_reg;
}

static void translate_loadraw(struct ir_insn *insn)
{
	enum val_type tdst = vtype_insn(insn);
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	struct ir_insn *dst_insn = insn_dst(insn);
	DBGASSERT(tdst == REG);
	extra->translated[0] = load_addr_to_reg(get_alloc_reg(dst_insn),
						insn->addr_val, insn->vr_type);
}

static void translate_loadimm_extra(struct ir_insn *insn)
{
	enum val_type tdst = vtype_insn(insn);
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	struct ir_insn *dst_insn = insn_dst(insn);
	DBGASSERT(tdst == REG);
	extra->translated[0].opcode = BPF_IMM | BPF_LD | BPF_DW;
	DBGASSERT(insn->imm_extra_type <= 0x6);
	extra->translated[0].src_reg = insn->imm_extra_type;
	extra->translated[0].dst_reg = get_alloc_reg(dst_insn);
	// 0 2 6 needs next
	if (insn->imm_extra_type == IR_LOADIMM_IMM64 ||
	    insn->imm_extra_type == IR_LOADIMM_MAP_VAL_FD ||
	    insn->imm_extra_type == IR_LOADIMM_MAP_VAL_IDX) {
		extra->translated[0].it = IMM64;
		extra->translated[0].imm64 = insn->imm64;
	} else {
		extra->translated[0].imm = insn->imm64 & 0xFFFFFFFF;
		extra->translated[0].it = IMM;
	}
}

static void translate_storeraw(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	// storeraw
	if (insn->addr_val.value.type == IR_VALUE_INSN) {
		// Store value in (address in the value)
		DBGASSERT(vtype(insn->addr_val.value) == REG);
		// Store value in the stack
		if (t0 == REG) {
			extra->translated[0] = store_reg_to_reg_mem(
				get_alloc_reg(insn->addr_val.value.data.insn_d),
				get_alloc_reg(v0.data.insn_d),
				insn->addr_val.offset, insn->vr_type);
		} else if (t0 == CONST) {
			extra->translated[0] = store_const_to_reg_mem(
				get_alloc_reg(insn->addr_val.value.data.insn_d),
				v0.data.constant_d, insn->addr_val.offset,
				insn->vr_type);
		} else {
			CRITICAL("Error");
		}
	} else {
		CRITICAL("Error");
	}
}

static void translate_alu(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	struct ir_value v1 = insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(v1) : UNDEF;
	enum val_type tdst = vtype_insn(insn);
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	struct ir_insn *dst_insn = insn_dst(insn);
	DBGASSERT(tdst == REG);
	DBGASSERT(t0 == REG);
	DBGASSERT(get_alloc_reg(dst_insn) == get_alloc_reg(v0.data.insn_d));
	if (t1 == REG) {
		extra->translated[0] = alu_reg(get_alloc_reg(dst_insn),
					       get_alloc_reg(v1.data.insn_d),
					       insn->alu_op,
					       alu_code(insn->op));
	} else if (t1 == CONST) {
		// Remove the instruction in some special cases
		if (insn->op == IR_INSN_ADD && v1.data.constant_d == 0) {
			extra->translated_num = 0;
			return;
		}
		extra->translated[0] = alu_imm(get_alloc_reg(dst_insn),
					       v1.data.constant_d, insn->alu_op,
					       alu_code(insn->op));
	} else {
		CRITICAL("Error");
	}
}

static void translate_assign(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	enum val_type tdst = vtype_insn(insn);
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	struct ir_insn *dst_insn = insn_dst(insn);

	// reg = const (alu)
	// reg = reg
	if (tdst == REG && t0 == CONST) {
		extra->translated[0] = translate_const_to_reg(
			get_alloc_reg(dst_insn), v0.data.constant_d,
			insn->alu_op);
	} else if (tdst == REG && t0 == REG) {
		if (get_alloc_reg(dst_insn) == get_alloc_reg(v0.data.insn_d)) {
			// Remove the instruction
			extra->translated_num = 0;
			return;
		}
		extra->translated[0] = translate_reg_to_reg(
			get_alloc_reg(dst_insn), get_alloc_reg(v0.data.insn_d));
	} else {
		CRITICAL("Error");
	}
}

static void translate_ret(struct ir_insn *insn)
{
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	extra->translated[0].opcode = BPF_EXIT | BPF_JMP;
}

static void translate_call(struct ir_insn *insn)
{
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	// Currently only support local helper functions
	extra->translated[0].opcode = BPF_CALL | BPF_JMP;
	extra->translated[0].it = IMM;
	extra->translated[0].imm = insn->fid;
}

static void translate_ja(struct ir_insn *insn)
{
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	extra->translated[0].opcode = BPF_JMP | BPF_JA;
}

static void translate_cond_jmp(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	struct ir_value v1 = insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(v1) : UNDEF;
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	DBGASSERT(t0 == REG || t1 == REG);
	if (t0 == REG) {
		if (t1 == REG) {
			extra->translated[0] =
				cond_jmp_reg(get_alloc_reg(v0.data.insn_d),
					     get_alloc_reg(v1.data.insn_d),
					     insn->alu_op, jmp_code(insn->op));
		} else if (t1 == CONST) {
			if (v1.const_type == IR_ALU_64) {
				CRITICAL("TODO");
			}
			extra->translated[0] =
				cond_jmp_imm(get_alloc_reg(v0.data.insn_d),
					     v1.data.constant_d, insn->alu_op,
					     jmp_code(insn->op));
		} else {
			CRITICAL("Error");
		}
	} else {
		DBGASSERT(t0 == CONST);
		DBGASSERT(t1 == REG);
		CRITICAL("TODO");
		// Probably we could switch?
		extra->translated[0] = cond_jmp_imm(
			get_alloc_reg(v1.data.insn_d), v0.data.constant_d,
			insn->alu_op, jmp_code(insn->op));
	}
}

static u32 bb_insn_cnt(struct ir_basic_block *bb)
{
	u32 cnt = 0;
	struct ir_insn *insn, *tmp;
	list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head, list_ptr) {
		if (insn->op == IR_INSN_ALLOC ||
		    insn->op == IR_INSN_ALLOCARRAY) {
			continue;
		} else {
			cnt++;
		}
	}
	return cnt;
}

static u32 bb_insn_critical_cnt(struct ir_basic_block *bb)
{
	u32 cnt = bb_insn_cnt(bb);
	while (bb->preds.num_elem <= 1) {
		if (bb->preds.num_elem == 0) {
			break;
		}
		struct ir_basic_block **tmp =
			bpf_ir_array_get_void(&bb->preds, 0);
		bb = *tmp;
		if (bb->flag & IR_BB_HAS_COUNTER) {
			break;
		}
		cnt += bb_insn_cnt(bb);
	}
	return cnt;
}

static void replace_builtin_const(struct bpf_ir_env *env,
				  struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			struct array operands = bpf_ir_get_operands(env, insn);
			struct ir_value **val;
			array_for(val, operands)
			{
				struct ir_value *v = *val;
				if (v->type == IR_VALUE_CONSTANT) {
					if (v->builtin_const ==
					    IR_BUILTIN_BB_INSN_CNT) {
						v->data.constant_d =
							bb_insn_cnt(bb);
					}
					if (v->builtin_const ==
					    IR_BUILTIN_BB_INSN_CRITICAL_CNT) {
						v->data.constant_d =
							bb_insn_critical_cnt(
								bb);
					}
				}
			}
			bpf_ir_array_free(&operands);
		}
	}
}

static void check_total_insn(struct bpf_ir_env *env, struct ir_function *fun)
{
	u32 cnt = 0;
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			struct ir_insn_cg_extra *extra = insn_cg(insn);
			cnt += extra->translated_num;
		}
	}
	if (cnt >= 1000000) {
		RAISE_ERROR("Too many instructions");
	}
}

static void translate(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			struct ir_insn_cg_extra *extra = insn_cg(insn);
			extra->translated_num = 1; // Default: 1 instruction
			if (insn->op == IR_INSN_ALLOC) {
				// Nothing to do
				extra->translated_num = 0;
			} else if (insn->op == IR_INSN_ALLOCARRAY) {
				// Nothing to do
				extra->translated_num = 0;
			} else if (insn->op == IR_INSN_STORE) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOAD) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_GETELEMPTR) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOADRAW) {
				translate_loadraw(insn);
			} else if (insn->op == IR_INSN_LOADIMM_EXTRA) {
				translate_loadimm_extra(insn);
			} else if (insn->op == IR_INSN_STORERAW) {
				translate_storeraw(insn);
			} else if (bpf_ir_is_alu(insn)) {
				translate_alu(insn);
			} else if (insn->op == IR_INSN_ASSIGN) {
				translate_assign(insn);
			} else if (insn->op == IR_INSN_RET) {
				translate_ret(insn);
			} else if (insn->op == IR_INSN_CALL) {
				translate_call(insn);
			} else if (insn->op == IR_INSN_JA) {
				translate_ja(insn);
			} else if (bpf_ir_is_cond_jmp(insn)) {
				translate_cond_jmp(insn);
			} else {
				RAISE_ERROR("No such instruction");
			}
		}
	}
}

// Spill all `allocarray` instructions
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
				struct ir_insn_cg_extra *extra = insn_cg(insn);
				DBGASSERT(extra->dst.data.insn_d ==
					  insn); // Ensure the dst is correct
				extra->allocated = true;
				// Calculate the offset
				u32 size = insn->array_num *
					   bpf_ir_sizeof_vr_type(insn->vr_type);
				if (size == 0) {
					RAISE_ERROR("Array size is 0");
				}
				offset -= (((size - 1) / 8) + 1) * 8;
				extra->spilled = offset;
				extra->spilled_size = size;
				extra->nonvr = true; // Array is not a VR
			}
		}
	}
}

// Interface Implementation

void bpf_ir_code_gen(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Init CG, start code generation
	init_cg(env, fun);
	CHECK_ERR();

	// Debugging settings
	fun->cg_info.spill_callee = 0;

	// Step 4: SSA Destruction
	remove_phi(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_dst(env, fun, "PHI Removal");
	prog_check_cg(env, fun);
	CHECK_ERR();

	// No more users, SSA structure is destroyed

	change_ret(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_dst(env, fun, "Changing ret");
	prog_check_cg(env, fun);
	CHECK_ERR();

	change_call(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_dst(env, fun, "Changing calls");
	CHECK_ERR();
	prog_check_cg(env, fun);
	CHECK_ERR();

	spill_array(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_dst(env, fun, "Spilling Arrays");
	CHECK_ERR();
	prog_check_cg(env, fun);
	CHECK_ERR();

	// print_ir_prog_reachable(fun);

	bool need_spill = true;
	int iterations = 0;

	while (need_spill) {
		PRINT_LOG(
			env,
			"\x1B[32m----- Register allocation iteration %d -----\x1B[0m\n",
			iterations);
		iterations++;
		// Step 5: Liveness Analysis
		liveness_analysis(env, fun);
		CHECK_ERR();

		// Step 6: Conflict Analysis
		conflict_analysis(env, fun);
		CHECK_ERR();
		if (env->opts.verbose > 2) {
			PRINT_LOG(env, "Conflicting graph:\n");
			bpf_ir_print_interference_graph(env, fun);
		}

		// Step 7: Graph coloring
		graph_coloring(env, fun);
		CHECK_ERR();

		if (env->opts.verbose > 2) {
			PRINT_LOG(env, "Conflicting graph (after coloring):\n");
			bpf_ir_print_interference_graph(env, fun);
		}
		CHECK_ERR();
		print_ir_prog_cg_alloc(env, fun, "After RA");

		if (env->opts.enable_coalesce) {
			bool need_rerun = coalescing(env, fun);
			CHECK_ERR();
			if (need_rerun) {
				PRINT_LOG(env, "Need to re-analyze...\n");
				clean_cg(env, fun);
				CHECK_ERR();
				continue;
			}
			prog_check_cg(env, fun);
			CHECK_ERR();
			print_ir_prog_cg_dst(env, fun,
					     "After Coalescing (dst)");
			print_ir_prog_cg_alloc(env, fun,
					       "After Coalescing (reg)");
		}

		// Step 8: Check if need to spill and spill
		need_spill = check_need_spill(env, fun);
		CHECK_ERR();
		print_ir_prog_cg_alloc(env, fun, "Spilling");
		CHECK_ERR();
		prog_check_cg(env, fun);
		CHECK_ERR();

		// print_ir_prog_cg_dst(env, fun, "After Spilling");
		if (need_spill) {
			// Still need to spill
			PRINT_LOG(env, "Need to spill...\n");
			clean_cg(env, fun);
			CHECK_ERR();
		}
	}

	// Register allocation finished (All registers are fixed)
	PRINT_LOG(env, "Register allocation finished in %d iterations\n",
		  iterations);
	print_ir_prog_cg_alloc(env, fun, "After RA & Spilling");
	// Step 9: Calculate stack size
	if (fun->cg_info.spill_callee) {
		calc_callee_num(fun);
	}
	calc_stack_size(fun);

	// Step 10: Shift raw stack operations
	add_stack_offset(env, fun, fun->cg_info.stack_offset);
	CHECK_ERR();
	print_ir_prog_cg_alloc(env, fun, "Shifting stack access");
	prog_check_cg(env, fun);
	CHECK_ERR();

	// Step 11: Spill callee saved registers
	if (fun->cg_info.spill_callee) {
		spill_callee(env, fun);
		CHECK_ERR();
		print_ir_prog_cg_alloc(env, fun, "Spilling callee-saved regs");
		prog_check_cg(env, fun);
		CHECK_ERR();
	}

	// Step 12: Normalize
	normalize(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_alloc(env, fun, "Normalization");
	prog_check_cg(env, fun);
	CHECK_ERR();

	replace_builtin_const(env, fun);
	CHECK_ERR();

	// Step 13: Direct Translation
	translate(env, fun);
	CHECK_ERR();

	check_total_insn(env, fun);
	CHECK_ERR();

	// Step 14: Relocation
	relocate(env, fun);
	CHECK_ERR();

	// Step 15: Synthesize
	synthesize(env, fun);
	CHECK_ERR();

	// Free CG resources
	free_cg_res(fun);
}

void bpf_ir_init_insn_cg(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_insn_cg_extra *extra = NULL;
	SAFE_MALLOC(extra, sizeof(struct ir_insn_cg_extra));
	insn->user_data = extra;
	// When init, the destination is itself
	extra->dst = bpf_ir_value_undef();
	if (!bpf_ir_is_void(insn)) {
		set_insn_dst(env, insn, insn);
	}

	INIT_ARRAY(&extra->adj, struct ir_insn *);
	extra->allocated = false;
	extra->spilled = 0;
	extra->alloc_reg = 0;
	INIT_ARRAY(&extra->gen, struct ir_insn *);
	INIT_ARRAY(&extra->kill, struct ir_insn *);
	INIT_ARRAY(&extra->in, struct ir_insn *);
	INIT_ARRAY(&extra->out, struct ir_insn *);
	extra->translated_num = 0;
	extra->nonvr = false;
}
