#include <linux/bpf_ir.h>

static int init_cg(struct ir_function *fun)
{
	int ret = 0;
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
			ret = bpf_ir_init_insn_cg(insn);
			if (ret) {
				return ret;
			}
		}
	}

	for (__u8 i = 0; i < MAX_BPF_REG; ++i) {
		SAFE_MALLOC(fun->cg_info.regs[i], sizeof(struct ir_insn));
		// Those should be read-only
		struct ir_insn *insn = fun->cg_info.regs[i];
		insn->op = IR_INSN_REG;
		insn->parent_bb = NULL;
		INIT_ARRAY(&insn->users, struct ir_insn *);
		insn->value_num = 0;
		ret = bpf_ir_init_insn_cg(insn);
		if (ret) {
			return ret;
		}
		struct ir_insn_cg_extra *extra = insn_cg(insn);
		extra->alloc_reg = i;
		extra->dst = insn;
		// Pre-colored registers are allocated
		extra->allocated = 1;
		extra->spilled = 0;
	}
	return 0;
}

static void free_insn_cg(struct ir_insn *insn)
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
			free_insn_cg(insn);
		}
	}

	for (__u8 i = 0; i < MAX_BPF_REG; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		bpf_ir_array_free(&insn->users);
		free_insn_cg(insn);
		free_proto(insn);
	}
}

static void clean_insn_cg(struct ir_insn *insn)
{
	struct ir_insn_cg_extra *extra = insn_cg(insn);
	bpf_ir_array_clear(&extra->adj);
	bpf_ir_array_clear(&extra->gen);
	bpf_ir_array_clear(&extra->kill);
	bpf_ir_array_clear(&extra->in);
	bpf_ir_array_clear(&extra->out);
}

static void clean_cg(struct ir_function *fun)
{
	struct ir_basic_block **pos = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			clean_insn_cg(insn);
			struct ir_insn_cg_extra *extra = insn_cg(insn);
			extra->allocated = 0;
			extra->spilled = 0;
			extra->alloc_reg = 0;
		}
	}

	for (__u8 i = 0; i < MAX_BPF_REG; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		clean_insn_cg(insn);
	}
	bpf_ir_array_clear(&fun->cg_info.all_var);
}

static void print_ir_prog_pre_cg(struct ir_function *fun, char *msg)
{
	PRINT_LOG("\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(fun, NULL, NULL, NULL);
}

static void print_ir_prog_cg_dst(struct ir_function *fun, char *msg)
{
	PRINT_LOG("\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(fun, NULL, NULL, print_ir_dst);
}

static void print_ir_prog_cg_alloc(struct ir_function *fun, char *msg)
{
	PRINT_LOG("\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(fun, NULL, NULL, print_ir_alloc);
}

static int synthesize(struct ir_function *fun)
{
	// The last step, synthesizes the program
	SAFE_MALLOC(fun->cg_info.prog,
		    fun->cg_info.prog_size * sizeof(struct bpf_insn));
	struct ir_basic_block **pos = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra *extra = insn_cg(insn);
			for (__u8 i = 0; i < extra->translated_num; ++i) {
				struct pre_ir_insn translated_insn =
					extra->translated[i];
				PRINT_LOG("Writing to insn %zu\n",
					  translated_insn.pos);
				struct bpf_insn *real_insn =
					&fun->cg_info.prog[translated_insn.pos];
				real_insn->code = translated_insn.opcode;
				real_insn->dst_reg = translated_insn.dst_reg;
				real_insn->src_reg = translated_insn.src_reg;
				real_insn->off = translated_insn.off;
				if (translated_insn.it == IMM) {
					real_insn->imm = translated_insn.imm;
				} else {
					// Wide instruction
					struct bpf_insn *real_insn2 =
						&fun->cg_info.prog
							 [translated_insn.pos +
							  1];
					real_insn->imm = translated_insn.imm64 &
							 0xffffffff;
					real_insn2->imm =
						translated_insn.imm64 >> 32;
				}
			}
		}
	}
	return 0;
}

// Convert from TSSA to CSSA
// Using "Method I" in paper "Translating Out of Static Single Assignment Form"
static void to_cssa(struct ir_function *fun)
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
				bpf_ir_array_push(&phi_insns, &insn);
			} else {
				break;
			}
		}
	}

	struct ir_insn **pos2;
	array_for(pos2, phi_insns)
	{
		struct ir_insn *insn = *pos2;
		// Create the moved PHI insn
		struct ir_insn *new_phi = create_phi_insn(insn, INSERT_FRONT);
		struct phi_value *pos3;
		array_for(pos3, insn->phi)
		{
			struct ir_insn *new_insn = create_assign_insn_bb(
				pos3->bb, pos3->value, INSERT_BACK_BEFORE_JMP);
			// Remove use
			val_remove_user(pos3->value, insn);
			phi_add_operand(new_phi, pos3->bb,
					bpf_ir_value_insn(new_insn));
		}

		bpf_ir_array_free(&insn->phi);
		insn->op = IR_INSN_ASSIGN;
		struct ir_value val = bpf_ir_value_insn(new_phi);
		insn->values[0] = val;
		insn->value_num = 1;
		val_add_user(val, insn);
	}

	bpf_ir_array_free(&phi_insns);
}

// Remove PHI insn
static void remove_phi(struct ir_function *fun)
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
				bpf_ir_array_push(&phi_insns, &insn);
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
			if (!repr) {
				repr = pos3->value.data.insn_d;
			} else {
				insn_cg(pos3->value.data.insn_d)->dst = repr;
			}
		}
		if (!repr) {
			CRITICAL("Empty Phi not removed!");
		}

		DBGASSERT(repr == insn_dst(repr));

		replace_all_usage(insn, bpf_ir_value_insn(repr));
		erase_insn(insn);
	}

	bpf_ir_array_free(&phi_insns);
}

static void coaleasing(struct ir_function *fun)
{
	struct ir_basic_block **pos;
	// For each BB
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *pos2, *tmp;
		// For each operation
		list_for_each_entry_safe(pos2, tmp, &bb->ir_insn_head,
					 list_ptr) {
			struct ir_insn *insn_dst = insn_dst(pos2);
			if (pos2->op == IR_INSN_ASSIGN) {
				if (pos2->values[0].type == IR_VALUE_INSN) {
					struct ir_insn *src =
						pos2->values[0].data.insn_d;
					DBGASSERT(src == insn_dst(src));
					if (insn_cg(src)->alloc_reg ==
					    insn_cg(insn_dst)->alloc_reg) {
						// Remove
						erase_insn_raw(pos2);
					}
				}
			}
		}
	}
}

static int is_insn_final(struct ir_insn *v1)
{
	return v1 == insn_dst(v1);
}

static void build_conflict(struct ir_insn *v1, struct ir_insn *v2)
{
	if (!is_insn_final(v1) || !is_insn_final(v2)) {
		CRITICAL("Can only build conflict on final values");
	}
	if (v1 == v2) {
		return;
	}
	bpf_ir_array_push_unique(&insn_cg(v1)->adj, &v2);
	bpf_ir_array_push_unique(&insn_cg(v2)->adj, &v1);
}

static void bpf_ir_print_interference_graph(struct ir_function *fun)
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
		if (!is_insn_final(insn)) {
			// Not final value, give up
			CRITICAL("Not Final Value!");
		}
		struct ir_insn_cg_extra *extra = insn_cg(insn);
		if (extra->allocated) {
			// Allocated VR
			PRINT_LOG("%%%zu(", insn->_insn_id);
			if (extra->spilled) {
				PRINT_LOG("sp-%zu", extra->spilled * 8);
			} else {
				PRINT_LOG("r%u", extra->alloc_reg);
			}
			PRINT_LOG("):");
		} else {
			// Pre-colored registers or unallocated VR
			print_insn_ptr_base(insn);
			PRINT_LOG(":");
		}
		struct ir_insn **pos2;
		array_for(pos2, insn_cg(insn)->adj)
		{
			struct ir_insn *adj_insn = *pos2;
			if (!is_insn_final(adj_insn)) {
				// Not final value, give up
				CRITICAL("Not Final Value!");
			}
			PRINT_LOG(" ");
			print_insn_ptr_base(adj_insn);
		}
		PRINT_LOG("\n");
	}
}

static void caller_constraint(struct ir_function *fun, struct ir_insn *insn)
{
	for (__u8 i = BPF_REG_0; i < BPF_REG_6; ++i) {
		// R0-R5 are caller saved register
		DBGASSERT(fun->cg_info.regs[i] ==
			  insn_dst(fun->cg_info.regs[i]));
		build_conflict(fun->cg_info.regs[i], insn);
	}
}

static void conflict_analysis(struct ir_function *fun)
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
								fun, *pos2);
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
						&fun->cg_info.all_var,
						&insn_dst);
				}
				struct ir_insn **pos3;
				array_for(pos3, insn_cg->out)
				{
					DBGASSERT(*pos3 == insn_dst(*pos3));
					build_conflict(insn_dst, *pos3);
				}
			}
		}
	}
}

static enum ir_vr_type alu_to_vr_type(enum ir_alu_type ty)
{
	if (ty == IR_ALU_32) {
		return IR_VR_TYPE_32;
	} else if (ty == IR_ALU_64) {
		return IR_VR_TYPE_64;
	} else {
		CRITICAL("Error");
	}
}

// Make register usage explicit
// Example:
// %x = add %y, %arg1
// arg1 is r0 at the beginning of the function
// We then add a new instruction to the beginning of the function.

static void explicit_reg(struct ir_function *fun)
{
	// fun is still in IR form
	// Before this step, users are correct
	// In this step we change some dsts
	// We need carefully handle the users
	// dsts are NOT users
	// Invariant: All operands are final values
	// Final value: v == dst(v)
	struct ir_basic_block **pos;
	// Maximum number of functions: MAX_FUNC_ARG
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_CALL) {
				for (__u8 i = 0; i < insn->value_num; ++i) {
					struct ir_value val = insn->values[i];
					struct ir_insn *new_insn =
						create_assign_insn_cg(
							insn, val,
							INSERT_FRONT);
					insn_cg(new_insn)->dst =
						fun->cg_info.regs[i + 1];
					val_remove_user(val, insn);
				}
				insn->value_num = 0; // Remove all operands
				struct ir_insn_cg_extra *extra = insn_cg(insn);
				extra->dst = NULL;
				if (insn->users.num_elem == 0) {
					continue;
				}
				struct ir_insn *new_insn = create_assign_insn_cg(
					insn,
					bpf_ir_value_insn(fun->cg_info.regs[0]),
					INSERT_BACK);
				replace_all_usage(insn,
						  bpf_ir_value_insn(new_insn));
			}

			if (insn->op == IR_INSN_RET) {
				// ret x
				// ==>
				// R0 = x
				// ret
				struct ir_insn *new_insn =
					create_assign_insn_cg(insn,
							      insn->values[0],
							      INSERT_FRONT);
				val_remove_user(insn->values[0], insn);
				insn_cg(new_insn)->dst = fun->cg_info.regs[0];
				insn->value_num = 0;
			}
		}
	}
	// Arg
	for (__u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		if (fun->function_arg[i]->users.num_elem > 0) {
			// Insert ASSIGN arg[i] at the beginning of the function
			struct ir_insn *new_insn = create_assign_insn_bb_cg(
				fun->entry,
				bpf_ir_value_insn(fun->cg_info.regs[i + 1]),
				INSERT_FRONT_AFTER_PHI);
			replace_all_usage(fun->function_arg[i],
					  bpf_ir_value_insn(new_insn));
		}
	}
}

static int compare_insn(const void *a, const void *b)
{
	struct ir_insn *ap = *(struct ir_insn **)a;
	struct ir_insn *bp = *(struct ir_insn **)b;
	return ap->_insn_id > bp->_insn_id;
}

static void graph_coloring(struct ir_function *fun)
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
		struct ir_insn **pos2;

		int used_reg[MAX_BPF_REG] = { 0 };
		struct array used_spill;
		INIT_ARRAY(&used_spill, size_t);
		array_for(pos2, extra->adj)
		{
			struct ir_insn *insn2 = *pos2; // Adj instruction
			struct ir_insn_cg_extra *extra2 = insn_cg(insn2);
			if (extra2->allocated) {
				if (extra2->spilled) {
					bpf_ir_array_push_unique(
						&used_spill, &extra2->spilled);
				} else {
					used_reg[extra2->alloc_reg] = 1;
				}
			}
		}
		__u8 need_spill = 1;
		for (__u8 i = 0; i < MAX_BPF_REG; i++) {
			if (!used_reg[i]) {
				extra->allocated = 1;
				PRINT_LOG("Allocate r%u for %%%zu\n", i,
					  insn->_insn_id);
				extra->alloc_reg = i;
				need_spill = 0;
				break;
			}
		}
		if (need_spill) {
			size_t sp = 1;
			while (1) {
				__u8 found = 1;
				size_t *pos3;
				array_for(pos3, used_spill)
				{
					if (*pos3 == sp) {
						sp++;
						found = 0;
						break;
					}
				}
				if (found) {
					extra->allocated = 1;
					extra->spilled = sp;
					break;
				}
			}
		}
		bpf_ir_array_free(&used_spill);
	}
}

// Live variable analysis

static void gen_kill(struct ir_function *fun)
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
			if (!is_void(pos2) && insn_dst) {
				bpf_ir_array_push_unique(&insn_cg->kill,
							 &insn_dst);
			}
			struct array value_uses = get_operands(pos2);
			struct ir_value **pos3;
			array_for(pos3, value_uses)
			{
				struct ir_value *val = *pos3;
				if (val->type == IR_VALUE_INSN) {
					struct ir_insn *insn = val->data.insn_d;
					DBGASSERT(insn == insn_dst(insn));
					bpf_ir_array_push_unique(&insn_cg->gen,
								 &insn);
					// array_erase_elem(&insn_cg->kill, insn);
				}
			}
			bpf_ir_array_free(&value_uses);
		}
	}
}

static int array_contains(struct array *arr, struct ir_insn *insn)
{
	struct ir_insn **pos;
	array_for(pos, (*arr))
	{
		if (*pos == insn) {
			return 1;
		}
	}
	return 0;
}

static struct array array_delta(struct array *a, struct array *b)
{
	struct array res;
	INIT_ARRAY(&res, struct ir_insn *);
	struct ir_insn **pos;
	array_for(pos, (*a))
	{
		struct ir_insn *insn = *pos;
		if (!array_contains(b, insn)) {
			bpf_ir_array_push(&res, &insn);
		}
	}
	return res;
}

static void merge_array(struct array *a, struct array *b)
{
	struct ir_insn **pos;
	array_for(pos, (*b))
	{
		struct ir_insn *insn = *pos;
		bpf_ir_array_push_unique(a, &insn);
	}
}

static int equal_set(struct array *a, struct array *b)
{
	if (a->num_elem != b->num_elem) {
		return 0;
	}
	struct ir_insn **pos;
	array_for(pos, (*a))
	{
		struct ir_insn *insn = *pos;
		if (!array_contains(b, insn)) {
			return 0;
		}
	}
	return 1;
}

static void in_out(struct ir_function *fun)
{
	int change = 1;
	// For each BB
	while (change) {
		change = 0;
		struct ir_basic_block **pos;
		array_for(pos, fun->reachable_bbs)
		{
			struct ir_basic_block *bb = *pos;
			struct ir_insn *insn;

			list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
				struct ir_insn_cg_extra *insn_cg =
					insn->user_data;
				struct array old_in = insn_cg->in;
				bpf_ir_array_clear(&insn_cg->out);

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
						merge_array(&insn_cg->out,
							    &insn2_cg->in);
					}
				} else {
					// Not last instruction
					struct ir_insn *next_insn = list_entry(
						insn->list_ptr.next,
						struct ir_insn, list_ptr);
					struct ir_insn_cg_extra *next_insn_cg =
						next_insn->user_data;
					merge_array(&insn_cg->out,
						    &next_insn_cg->in);
				}
				struct array out_kill_delta = array_delta(
					&insn_cg->out, &insn_cg->kill);
				bpf_ir_array_clone(&insn_cg->in, &insn_cg->gen);
				merge_array(&insn_cg->in, &out_kill_delta);
				// Check for change
				if (!equal_set(&insn_cg->in, &old_in)) {
					change = 1;
				}
				// Collect grabage
				bpf_ir_array_free(&out_kill_delta);
				bpf_ir_array_free(&old_in);
			}
		}
	}
}

static void print_insn_extra(struct ir_insn *insn)
{
	struct ir_insn_cg_extra *insn_cg = insn->user_data;
	if (insn_cg == NULL) {
		CRITICAL("NULL user data");
	}
	PRINT_LOG("--\nGen:");
	struct ir_insn **pos;
	array_for(pos, insn_cg->gen)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG(" ");
		print_insn_ptr_base(insn);
	}
	PRINT_LOG("\nKill:");
	array_for(pos, insn_cg->kill)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG(" ");
		print_insn_ptr_base(insn);
	}
	PRINT_LOG("\nIn:");
	array_for(pos, insn_cg->in)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG(" ");
		print_insn_ptr_base(insn);
	}
	PRINT_LOG("\nOut:");
	array_for(pos, insn_cg->out)
	{
		struct ir_insn *insn = *pos;
		PRINT_LOG(" ");
		print_insn_ptr_base(insn);
	}
	PRINT_LOG("\n-------------\n");
}

static void liveness_analysis(struct ir_function *fun)
{
	// TODO: Encode Calling convention into GEN KILL
	gen_kill(fun);
	in_out(fun);
	PRINT_LOG("--------------\n");
	print_ir_prog_advanced(fun, NULL, print_insn_extra, print_ir_dst);
	print_ir_prog_advanced(fun, NULL, NULL, print_ir_dst);
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
		return STACK;
	} else {
		return REG;
	}
}

static enum val_type vtype(struct ir_value val)
{
	if (val.type == IR_VALUE_INSN) {
		return vtype_insn(val.data.insn_d);
	} else if (val.type == IR_VALUE_CONSTANT) {
		return CONST;
	} else if (val.type == IR_VALUE_STACK_PTR) {
		return REG;
	} else {
		CRITICAL("No such value type for dst");
	}
}

// Normalization

static void normalize(struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_value *v0 = &insn->values[0];
			struct ir_value *v1 = &insn->values[1];
			enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) :
								  UNDEF;
			enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) :
								  UNDEF;
			enum val_type tdst = vtype_insn(insn);
			struct ir_insn *dst_insn = insn_dst(insn);
			if (insn->op == IR_INSN_ALLOC) {
				// Skip
			} else if (insn->op == IR_INSN_STORE) {
				// Should be converted to ASSIGN
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOAD) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOADRAW) {
				// OK
			} else if (insn->op == IR_INSN_STORERAW) {
				// OK
			} else if (is_alu(insn)) {
				// Binary ALU
				if (t0 == STACK && t1 == CONST) {
					// reg1 = add stack const
					// ==>
					// reg1 = stack
					// reg1 = add reg1 const
					struct ir_insn *new_insn =
						create_assign_insn_cg(
							insn, *v0,
							INSERT_FRONT);
					insn_cg(new_insn)->dst = dst_insn;
					new_insn->vr_type =
						alu_to_vr_type(insn->alu);
					v0->type = IR_VALUE_INSN;
					v0->data.insn_d = dst_insn;
				} else if (t0 == REG && t1 == REG) {
					// reg1 = add reg2 reg3
					__u8 reg1 =
						insn_cg(dst_insn)->alloc_reg;
					__u8 reg2 = insn_cg(v0->data.insn_d)
							    ->alloc_reg;
					__u8 reg3 = insn_cg(v1->data.insn_d)
							    ->alloc_reg;
					if (reg1 != reg2) {
						if (reg1 == reg3) {
							// Exchange reg2 and reg3
							struct ir_value tmp =
								*v0;
							*v0 = *v1;
							*v1 = tmp;
						} else {
							// reg1 = add reg2 reg3
							// ==>
							// reg1 = reg2
							// reg1 = add reg1 reg3
							struct ir_insn *new_insn =
								create_assign_insn_cg(
									insn,
									*v0,
									INSERT_FRONT);
							DBGASSERT(
								dst_insn ==
								fun->cg_info.regs
									[reg1]);
							insn_cg(new_insn)->dst =
								dst_insn;
							v0->type =
								IR_VALUE_INSN;
							v0->data.insn_d =
								dst_insn;
						}
					}
				} else if (t0 == REG && t1 == CONST) {
					if (insn_cg(v0->data.insn_d)->alloc_reg !=
					    insn_cg(dst_insn)->alloc_reg) {
						// reg1 = add reg2 const
						// ==>
						// reg1 = reg2
						// reg1 = add reg1 const
						struct ir_insn *new_insn =
							create_assign_insn_cg(
								insn, *v0,
								INSERT_FRONT);
						insn_cg(new_insn)->dst =
							dst_insn;
						v0->type = IR_VALUE_INSN;
						v0->data.insn_d = dst_insn;
					}
				} else {
					CRITICAL("Error");
				}
			} else if (insn->op == IR_INSN_ASSIGN) {
				// stack = reg
				// stack = const
				// reg = const
				// reg = stack
				// reg = reg
				if (tdst == STACK) {
					DBGASSERT(t0 != STACK);
					// Change to STORERAW
					insn->op = IR_INSN_STORERAW;
					insn->addr_val.value =
						bpf_ir_value_stack_ptr();
					insn->addr_val.offset =
						-insn_cg(dst_insn)->spilled * 8;
				} else {
					if (t0 == STACK) {
						// Change to LOADRAW
						insn->op = IR_INSN_LOADRAW;
						insn->addr_val.value =
							bpf_ir_value_stack_ptr();
						insn->addr_val.offset =
							-insn_cg(v0->data.insn_d)
								 ->spilled *
							8;
					}
				}
			} else if (insn->op == IR_INSN_RET) {
				// OK
			} else if (insn->op == IR_INSN_CALL) {
				// OK
			} else if (insn->op == IR_INSN_JA) {
				// OK
			} else if (insn->op >= IR_INSN_JEQ &&
				   insn->op < IR_INSN_PHI) {
				// jmp reg const/reg
				// or
				// jmp const/reg reg
				// OK
			} else {
				CRITICAL("No such instruction");
			}
		}
	}
}

// Relocate BB
static void calc_pos(struct ir_function *fun)
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
			for (__u8 i = 0; i < insn_extra->translated_num; ++i) {
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
	fun->cg_info.prog_size = ipos;
}

static void relocate(struct ir_function *fun)
{
	calc_pos(fun);
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
			if (is_cond_jmp(insn)) {
				DBGASSERT(insn_extra->translated_num == 1);
				size_t target = bpf_ir_bb_cg(insn->bb2)->pos;
				insn_extra->translated[0].off =
					target - insn_extra->translated[0].pos -
					1;
			}
		}
	}
}

static void load_stack_to_r0(struct ir_function *fun, struct ir_insn *insn,
			     struct ir_value *val, enum ir_vr_type vtype)
{
	struct ir_insn *tmp = create_assign_insn_cg(insn, *val, INSERT_FRONT);
	tmp->vr_type = vtype;
	insn_cg(tmp)->dst = fun->cg_info.regs[0];

	val->type = IR_VALUE_INSN;
	val->data.insn_d = fun->cg_info.regs[0];
}

static void add_stack_offset_vr(struct ir_function *fun, size_t num)
{
	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		if (extra->spilled > 0) {
			extra->spilled += num;
		}
	}
}

static void spill_callee(struct ir_function *fun)
{
	// Spill Callee saved registers if used
	__u8 reg_used[MAX_BPF_REG] = { 0 };

	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		reg_used[extra->alloc_reg] = 1;
	}
	size_t off = 0;
	for (__u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
		if (reg_used[i]) {
			off++;
		}
	}
	DBGASSERT(off == fun->cg_info.callee_num);
	add_stack_offset_vr(fun, off);
	off = 0;
	for (__u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
		// All callee saved registers
		if (reg_used[i]) {
			off++;
			// Spill at sp-off
			// struct ir_insn *st = create_assign_insn_bb_cg(
			//     fun->entry, ir_value_insn(fun->cg_info.regs[i]), INSERT_FRONT);
			struct ir_insn *st = create_insn_base_cg(fun->entry);
			insert_at_bb(st, fun->entry, INSERT_FRONT);
			st->op = IR_INSN_STORERAW;
			st->values[0] = bpf_ir_value_insn(fun->cg_info.regs[i]);
			st->value_num = 1;
			st->vr_type = IR_VR_TYPE_64;
			struct ir_value val;
			val.type = IR_VALUE_STACK_PTR;
			st->addr_val.value = val;
			st->addr_val.offset = -off * 8;
			struct ir_insn_cg_extra *extra = insn_cg(st);
			extra->dst = NULL;

			struct ir_basic_block **pos2;
			array_for(pos2, fun->end_bbs)
			{
				struct ir_basic_block *bb = *pos2;
				struct ir_insn *ld = create_insn_base_cg(bb);
				insert_at_bb(ld, bb, INSERT_BACK_BEFORE_JMP);
				ld->op = IR_INSN_LOADRAW;
				ld->value_num = 0;
				ld->vr_type = IR_VR_TYPE_64;
				struct ir_value val;
				val.type = IR_VALUE_STACK_PTR;
				ld->addr_val.value = val;
				ld->addr_val.offset = -off * 8;

				extra = insn_cg(ld);
				extra->dst = fun->cg_info.regs[i];
			}
		}
	}
}

static int check_need_spill(struct ir_function *fun)
{
	// Check if all instruction values are OK for translating
	int res = 0;
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_value *v0 = &insn->values[0];
			struct ir_value *v1 = &insn->values[1];
			enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) :
								  UNDEF;
			enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) :
								  UNDEF;
			enum val_type tdst = vtype_insn(insn);
			struct ir_insn_cg_extra *extra = insn_cg(insn);
			struct ir_insn *dst_insn = insn_dst(insn);
			if (insn->op == IR_INSN_ALLOC) {
				// dst = alloc <size>
				// Nothing to do
			} else if (insn->op == IR_INSN_STORE) {
				// store v0(dst) v1
				// Eequivalent to `v0 = v1`
				insn->op = IR_INSN_ASSIGN;
				DBGASSERT(
					v0->type ==
					IR_VALUE_INSN); // Should be guaranteed by prog_check
				DBGASSERT(v0->data.insn_d->op == IR_INSN_ALLOC);
				insn->vr_type = v0->data.insn_d->vr_type;
				extra->dst = v0->data.insn_d;
				insn->value_num = 1;
				*v0 = *v1;
				res = 1;
			} else if (insn->op == IR_INSN_LOAD) {
				// stack = load stack
				// stack = load reg
				// reg = load reg
				// reg = load stack
				insn->op = IR_INSN_ASSIGN;
				DBGASSERT(
					v0->type ==
					IR_VALUE_INSN); // Should be guaranteed by prog_check
				DBGASSERT(v0->data.insn_d->op == IR_INSN_ALLOC);
				insn->vr_type = v0->data.insn_d->vr_type;
				res = 1;
			} else if (insn->op == IR_INSN_LOADRAW) {
				// Load from memory
				// reg = loadraw reg ==> OK
				// reg = loadraw const ==> OK

				// stack = loadraw addr
				// ==>
				// R0 = loadraw addr
				// stack = R0

				// stack = loadraw stack
				// ==>
				// R0 = stack
				// R0 = loadraw R0
				// stack = R0
				if (tdst == STACK) {
					extra->dst = fun->cg_info.regs[0];
					struct ir_insn *tmp =
						create_assign_insn_cg(
							insn,
							bpf_ir_value_insn(
								fun->cg_info
									.regs[0]),
							INSERT_BACK);
					insn_cg(tmp)->dst = dst_insn;
					tmp->vr_type = insn->vr_type;
					res = 1;
				}
				if (vtype(insn->addr_val.value) == STACK) {
					// Question: are all memory address 64 bits?
					load_stack_to_r0(fun, insn,
							 &insn->addr_val.value,
							 IR_VR_TYPE_64);
					res = 1;
				}
			} else if (insn->op == IR_INSN_STORERAW) {
				// Store some value to memory
				// store ptr reg ==> OK
				// store ptr stack

				// store stackptr stack
				// ==> TODO!
				if (t0 == STACK &&
				    vtype(insn->addr_val.value) == STACK) {
					CRITICAL("TODO!");
				}
				if (t0 == CONST &&
				    insn->vr_type == IR_VR_TYPE_64) {
					CRITICAL("Not supported");
				}
				// Question: are all memory address 64 bits?
				if (t0 == STACK) {
					load_stack_to_r0(fun, insn, v0,
							 IR_VR_TYPE_64);
					res = 1;
				}
				if (vtype(insn->addr_val.value) == CONST) {
					CRITICAL("Not Supported");
				}
				if (vtype(insn->addr_val.value) == STACK) {
					load_stack_to_r0(fun, insn,
							 &insn->addr_val.value,
							 IR_VR_TYPE_64);
					res = 1;
				}
			} else if (is_alu(insn)) {
				// Binary ALU
				// reg = add reg reg
				// reg = add reg const
				// There should be NO stack
				if (tdst == STACK) {
					// stack = add ? ?
					// ==>
					// R0 = add ? ?
					// stack = R0
					extra->dst = fun->cg_info.regs[0];
					struct ir_insn *tmp =
						create_assign_insn_cg(
							insn,
							bpf_ir_value_insn(
								fun->cg_info
									.regs[0]),
							INSERT_BACK);
					tmp->vr_type =
						alu_to_vr_type(insn->alu);
					insn_cg(tmp)->dst = dst_insn;
					res = 1;
				} else {
					if ((t0 != REG && t1 == REG) ||
					    (t0 == CONST && t1 == STACK)) {
						// reg = add !reg reg
						// ==>
						// reg = add reg !reg
						struct ir_value tmp = *v0;
						*v0 = *v1;
						*v1 = tmp;
						enum val_type ttmp = t0;
						t0 = t1;
						t1 = ttmp;
						// No need to spill here
					}
					if (t0 == REG) {
						// reg = add reg reg ==> OK
						// reg = add reg const ==> OK

						// reg1 = add reg2 stack
						// ==>
						// If reg1 != reg2,
						//   reg1 = stack
						//   reg1 = add reg2 reg1
						// Else
						//   Choose reg3 != reg1,
						//   reg3 = stack
						//   reg1 = add reg1 reg3
						if (t1 == STACK) {
							__u8 reg1 =
								insn_cg(dst_insn)
									->alloc_reg;
							__u8 reg2 =
								insn_cg(v0->data.insn_d)
									->alloc_reg;
							struct ir_insn *new_insn =
								create_assign_insn_cg(
									insn,
									*v1,
									INSERT_FRONT);
							new_insn->vr_type =
								alu_to_vr_type(
									insn->alu);
							v1->type =
								IR_VALUE_INSN;
							if (reg1 == reg2) {
								__u8 reg =
									reg1 == 0 ?
										1 :
										0;
								insn_cg(new_insn)
									->dst =
									fun->cg_info
										.regs[reg];
								v1->data.insn_d =
									fun->cg_info
										.regs[reg];
							} else {
								insn_cg(new_insn)
									->dst =
									fun->cg_info
										.regs[reg1];
								v1->data.insn_d =
									fun->cg_info
										.regs[reg1];
							}
							res = 1;
						}
					} else {
						// reg = add const const ==> OK
						// reg = add c1 c2
						// ==>
						// reg = c1
						// reg = add reg c2
						// OK

						// reg = add stack stack
						if (t0 == STACK &&
						    t1 == STACK) {
							// reg1 = add stack1 stack2
							// ==>
							// Found reg2 != reg1
							// reg1 = stack1
							// reg1 = add reg1 stack2
							__u8 reg1 =
								insn_cg(dst_insn)
									->alloc_reg;
							struct ir_insn *new_insn =
								create_assign_insn_cg(
									insn,
									*v0,
									INSERT_FRONT);
							new_insn->vr_type =
								alu_to_vr_type(
									insn->alu);
							insn_cg(new_insn)->dst =
								fun->cg_info.regs
									[reg1];
							v0->type =
								IR_VALUE_INSN;
							v0->data.insn_d =
								fun->cg_info.regs
									[reg1];
							res = 1;
						}
						// reg = add stack const ==> OK
						// ==>
						// reg = stack
						// reg = add reg const
					}
				}
			} else if (insn->op == IR_INSN_ASSIGN) {
				// stack = reg (sized)
				// stack = const (sized)
				// reg = const (alu)
				// reg = stack (sized)
				// reg = reg
				if (tdst == STACK && t0 == STACK) {
					// Both stack positions are managed by us
					load_stack_to_r0(fun, insn, v0,
							 IR_VR_TYPE_64);
					res = 1;
				}
				if (tdst == STACK && t0 == CONST) {
					if (insn->vr_type == IR_VR_TYPE_64) {
						// First load to R0
						struct ir_insn *new_insn =
							create_assign_insn_cg(
								insn, *v0,
								INSERT_FRONT);
						new_insn->vr_type =
							insn->vr_type;
						insn_cg(new_insn)->dst =
							fun->cg_info.regs[0];
						v0->type = IR_VALUE_INSN;
						v0->data.insn_d =
							fun->cg_info.regs[0];
						res = 1;
					}
				}
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
			} else if (is_cond_jmp(insn)) {
				// jmp reg const/reg
				__u8 switched = 0;
				if ((t0 != REG && t1 == REG) ||
				    (t0 == CONST && t1 == STACK)) {
					switched = 1;
					struct ir_value tmp = *v0;
					*v0 = *v1;
					*v1 = tmp;
					enum val_type ttmp = t0;
					t0 = t1;
					t1 = ttmp;
					// No need to spill here
				}

				if (t0 == REG) {
					// jmp reg reg ==> OK
					// jmp reg const ==> OK
					// jmp reg stack
					// ==>
					// reg2 = stack
					// jmp reg reg2
					if (t1 == STACK) {
						__u8 reg1 =
							insn_cg(v0->data.insn_d)
								->alloc_reg;
						__u8 reg2 = reg1 == 0 ? 1 : 0;
						struct ir_insn *new_insn =
							create_assign_insn_cg(
								insn, *v1,
								INSERT_FRONT);
						new_insn->vr_type =
							alu_to_vr_type(
								insn->alu);
						insn_cg(new_insn)->dst =
							fun->cg_info.regs[reg2];
						v1->type = IR_VALUE_INSN;
						v1->data.insn_d =
							fun->cg_info.regs[reg2];
						res = 1;
					}
				} else {
					// jmp const1 const2
					// ==>
					// %tmp = const1
					// jmp %tmp const2
					if (t0 == CONST && t1 == CONST) {
						struct ir_insn *new_insn =
							create_assign_insn_cg(
								insn, *v0,
								INSERT_FRONT);
						new_insn->vr_type =
							alu_to_vr_type(
								insn->alu);
						v0->type = IR_VALUE_INSN;
						v0->data.insn_d = new_insn;
						res = 1;
					}
					// jmp stack const
					if (t0 == STACK && t1 == CONST) {
						load_stack_to_r0(
							fun, insn, v0,
							alu_to_vr_type(
								insn->alu));
						res = 1;
					}
					// jmp stack1 stack2
					// ==>
					// R0 = stack1
					// R1 = stack2
					// jmp R0 R1
					if (t0 == STACK && t1 == STACK) {
						load_stack_to_r0(
							fun, insn, v0,
							alu_to_vr_type(
								insn->alu));
						res = 1;
					}
				}
				if (switched) {
					// Switch back
					struct ir_value tmp = *v0;
					*v0 = *v1;
					*v1 = tmp;
				}
			} else {
				CRITICAL("No such instruction");
			}
		}
	}
	return res;
}

static void calc_callee_num(struct ir_function *fun)
{
	__u8 reg_used[MAX_BPF_REG] = { 0 };

	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		reg_used[extra->alloc_reg] = 1;
	}
	size_t off = 0;
	for (__u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
		if (reg_used[i]) {
			off++;
		}
	}
	fun->cg_info.callee_num = off;
}

static void calc_stack_size(struct ir_function *fun)
{
	// Check callee
	size_t off = 0;
	if (fun->cg_info.spill_callee) {
		off += fun->cg_info.callee_num * 8;
	}
	// Check all VR
	size_t max = 0;
	struct ir_insn **pos;
	array_for(pos, fun->cg_info.all_var)
	{
		struct ir_insn_cg_extra *extra = insn_cg(*pos);
		if (extra->spilled > 0) {
			// Spilled!
			if (extra->spilled > max) {
				max = extra->spilled;
			}
		}
	}
	fun->cg_info.stack_offset = -(off + max * 8);
	PRINT_LOG("Stack size: %d\n", fun->cg_info.stack_offset);
}

static void add_stack_offset_pre_cg(struct ir_function *fun)
{
	// Pre CG
	struct array users = fun->sp_users;
	struct ir_insn **pos;
	array_for(pos, users)
	{
		struct ir_insn *insn = *pos;

		if (insn->op == IR_INSN_LOADRAW ||
		    insn->op == IR_INSN_STORERAW) {
			// Also need to check if the value points to an INSN or a STACKPTR
			// insn->addr_val.offset += offset;
			continue;
		}
		struct array value_uses = get_operands(insn);
		struct ir_value **pos2;
		array_for(pos2, value_uses)
		{
			struct ir_value *val = *pos2;
			if (val->type == IR_VALUE_STACK_PTR) {
				// Stack pointer as value
				struct ir_value new_val;
				new_val.type = IR_VALUE_CONSTANT_RAWOFF;
				struct ir_insn *new_insn = create_bin_insn(
					insn, *val, new_val, IR_INSN_ADD,
					IR_ALU_32, INSERT_FRONT);
				new_val.type = IR_VALUE_INSN;
				new_val.data.insn_d = new_insn;
				*val = new_val;
			}
		}
		bpf_ir_array_free(&value_uses);
	}
}

static void add_stack_offset(struct ir_function *fun, __s16 offset)
{
	struct array users = fun->sp_users;
	struct ir_insn **pos;
	array_for(pos, users)
	{
		struct ir_insn *insn = *pos;

		if (insn->op == IR_INSN_LOADRAW ||
		    insn->op == IR_INSN_STORERAW) {
			if (insn->addr_val.value.type == IR_VALUE_STACK_PTR) {
				insn->addr_val.offset += offset;
				continue;
			}
		}
		struct array value_uses = get_operands(insn);
		struct ir_value **pos2;
		array_for(pos2, value_uses)
		{
			struct ir_value *val = *pos2;
			DBGASSERT(val->type != IR_VALUE_STACK_PTR);
			if (val->type == IR_VALUE_CONSTANT_RAWOFF) {
				// Stack pointer as value
				val->data.constant_d = offset;
			}
		}
		bpf_ir_array_free(&value_uses);
	}
}

static struct pre_ir_insn load_reg_to_reg(__u8 dst, __u8 src)
{
	// MOV dst src
	struct pre_ir_insn insn;
	insn.opcode = BPF_MOV | BPF_X | BPF_ALU64;
	insn.dst_reg = dst;
	insn.src_reg = src;
	return insn;
}

static struct pre_ir_insn load_const_to_reg(__u8 dst, __s64 data,
					    enum ir_alu_type type)
{
	// MOV dst imm
	struct pre_ir_insn insn;
	insn.dst_reg = dst;
	if (type == IR_ALU_64) {
		insn.it = IMM64;
		insn.imm64 = data;
		insn.opcode = BPF_MOV | BPF_K | BPF_ALU64;
	} else {
		insn.it = IMM;
		insn.imm = data;
		insn.opcode = BPF_MOV | BPF_K | BPF_ALU;
	}
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

static struct pre_ir_insn
load_addr_to_reg(__u8 dst, struct ir_address_value addr, enum ir_vr_type type)
{
	// MOV dst src
	struct pre_ir_insn insn;
	insn.dst_reg = dst;
	insn.off = addr.offset;
	int size = vr_type_to_size(type);
	if (addr.value.type == IR_VALUE_STACK_PTR) {
		insn.src_reg = BPF_REG_10;
		insn.opcode = BPF_LDX | size | BPF_MEM;
	} else if (addr.value.type == IR_VALUE_INSN) {
		// Must be REG
		DBGASSERT(vtype(addr.value) == REG);
		// Load reg (addr) to reg
		insn.src_reg = insn_cg(addr.value.data.insn_d)->alloc_reg;
		insn.opcode = BPF_LDX | size | BPF_MEM;
	} else if (addr.value.type == IR_VALUE_CONSTANT) {
		// Must be U64
		insn.it = IMM64;
		insn.imm64 = addr.value.data.constant_d;
		insn.opcode = BPF_IMM | size | BPF_LD;
	} else {
		CRITICAL("Error");
	}
	return insn;
}

static struct pre_ir_insn store_reg_to_reg_mem(__u8 dst, __u8 src, __s16 offset,
					       enum ir_vr_type type)
{
	struct pre_ir_insn insn;
	int size = vr_type_to_size(type);
	insn.src_reg = src;
	insn.off = offset;
	insn.opcode = BPF_STX | size | BPF_MEM;
	insn.dst_reg = dst;
	return insn;
}

static struct pre_ir_insn
store_const_to_reg_mem(__u8 dst, __s64 val, __s16 offset, enum ir_vr_type type)
{
	struct pre_ir_insn insn;
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
	default:
		CRITICAL("Error");
	}
}

static struct pre_ir_insn alu_reg(__u8 dst, __u8 src, enum ir_alu_type type,
				  int opcode)
{
	struct pre_ir_insn insn;
	insn.dst_reg = dst;
	insn.src_reg = src;
	int alu_class = type == IR_ALU_64 ? BPF_ALU64 : BPF_ALU;
	insn.opcode = opcode | BPF_X | alu_class;
	return insn;
}

static struct pre_ir_insn alu_imm(__u8 dst, __s64 src, enum ir_alu_type type,
				  int opcode)
{
	struct pre_ir_insn insn;
	insn.dst_reg = dst;
	insn.src_reg = src;
	int alu_class = type == IR_ALU_64 ? BPF_ALU64 : BPF_ALU;
	if (type == IR_ALU_64) {
		insn.it = IMM64;
		insn.imm64 = src;
	} else {
		insn.it = IMM;
		insn.imm = src;
	}
	insn.opcode = opcode | BPF_K | alu_class;
	return insn;
}

static struct pre_ir_insn cond_jmp_reg(__u8 dst, __u8 src,
				       enum ir_alu_type type, int opcode)
{
	struct pre_ir_insn insn;
	insn.dst_reg = dst;
	insn.src_reg = src;
	int alu_class = type == IR_ALU_64 ? BPF_JMP : BPF_JMP32;
	insn.opcode = opcode | alu_class | BPF_X;
	return insn;
}

static struct pre_ir_insn cond_jmp_imm(__u8 dst, __s64 src,
				       enum ir_alu_type type, int opcode)
{
	struct pre_ir_insn insn;
	insn.dst_reg = dst;
	insn.src_reg = src;
	int alu_class = type == IR_ALU_64 ? BPF_JMP : BPF_JMP32;
	if (type == IR_ALU_64) {
		insn.it = IMM64;
		insn.imm64 = src;
	} else {
		insn.it = IMM;
		insn.imm = src;
	}
	insn.opcode = opcode | alu_class | BPF_K;
	return insn;
}

static __u8 get_alloc_reg(struct ir_insn *insn)
{
	return insn_cg(insn)->alloc_reg;
}

static void translate(struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_value v0 = insn->values[0];
			struct ir_value v1 = insn->values[1];
			enum val_type t0 = insn->value_num >= 1 ? vtype(v0) :
								  UNDEF;
			enum val_type t1 = insn->value_num >= 2 ? vtype(v1) :
								  UNDEF;
			enum val_type tdst = vtype_insn(insn);
			struct ir_insn_cg_extra *extra = insn_cg(insn);
			struct ir_insn *dst_insn = insn_dst(insn);
			extra->translated_num = 1; // Default: 1 instruction
			if (insn->op == IR_INSN_ALLOC) {
				// Nothing to do
				extra->translated_num = 0;
			} else if (insn->op == IR_INSN_STORE) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOAD) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOADRAW) {
				DBGASSERT(tdst == REG);
				extra->translated[0] = load_addr_to_reg(
					get_alloc_reg(dst_insn), insn->addr_val,
					insn->vr_type);
			} else if (insn->op == IR_INSN_STORERAW) {
				// storeraw
				if (insn->addr_val.value.type ==
				    IR_VALUE_STACK_PTR) {
					// Store value in the stack
					if (t0 == REG) {
						extra->translated
							[0] = store_reg_to_reg_mem(
							BPF_REG_10,
							get_alloc_reg(
								v0.data.insn_d),
							insn->addr_val.offset,
							insn->vr_type);
					} else if (t0 == CONST) {
						extra->translated[0] =
							store_const_to_reg_mem(
								BPF_REG_10,
								v0.data.constant_d,
								insn->addr_val
									.offset,
								insn->vr_type);
					} else {
						CRITICAL("Error");
					}
				} else if (insn->addr_val.value.type ==
					   IR_VALUE_INSN) {
					// Store value in (address in the value)
					DBGASSERT(vtype(insn->addr_val.value) ==
						  REG);
					// Store value in the stack
					if (t0 == REG) {
						extra->translated
							[0] = store_reg_to_reg_mem(
							get_alloc_reg(
								insn->addr_val
									.value
									.data
									.insn_d),
							get_alloc_reg(
								v0.data.insn_d),
							insn->addr_val.offset,
							insn->vr_type);
					} else if (t0 == CONST) {
						extra->translated
							[0] = store_const_to_reg_mem(
							get_alloc_reg(
								insn->addr_val
									.value
									.data
									.insn_d),
							v0.data.constant_d,
							insn->addr_val.offset,
							insn->vr_type);
					} else {
						CRITICAL("Error");
					}
				} else {
					CRITICAL("Error");
				}
			} else if (insn->op >= IR_INSN_ADD &&
				   insn->op < IR_INSN_CALL) {
				DBGASSERT(tdst == REG);
				DBGASSERT(t0 == REG);
				DBGASSERT(get_alloc_reg(dst_insn) ==
					  get_alloc_reg(v0.data.insn_d));
				if (t1 == REG) {
					extra->translated[0] = alu_reg(
						get_alloc_reg(dst_insn),
						get_alloc_reg(v1.data.insn_d),
						insn->alu, alu_code(insn->op));
				} else if (t1 == CONST) {
					extra->translated[0] = alu_imm(
						get_alloc_reg(dst_insn),
						v1.data.constant_d, insn->alu,
						alu_code(insn->op));
				} else {
					CRITICAL("Error");
				}
			} else if (insn->op == IR_INSN_ASSIGN) {
				// reg = const (alu)
				// reg = reg
				if (tdst == REG && t0 == CONST) {
					extra->translated[0] =
						load_const_to_reg(
							get_alloc_reg(dst_insn),
							v0.data.constant_d,
							insn->alu);
				} else if (tdst == REG && t0 == REG) {
					extra->translated[0] = load_reg_to_reg(
						get_alloc_reg(dst_insn),
						get_alloc_reg(v0.data.insn_d));
				} else {
					CRITICAL("Error");
				}
			} else if (insn->op == IR_INSN_RET) {
				extra->translated[0].opcode = BPF_EXIT |
							      BPF_JMP;
			} else if (insn->op == IR_INSN_CALL) {
				// Currently only support local helper functions
				extra->translated[0].opcode = BPF_CALL |
							      BPF_JMP;
				extra->translated[0].it = IMM;
				extra->translated[0].imm = insn->fid;
			} else if (insn->op == IR_INSN_JA) {
				extra->translated[0].opcode = BPF_JMP | BPF_JA;
			} else if (insn->op >= IR_INSN_JEQ &&
				   insn->op < IR_INSN_PHI) {
				DBGASSERT(t0 == REG || t1 == REG);
				if (t0 == REG) {
					if (t1 == REG) {
						extra->translated
							[0] = cond_jmp_reg(
							get_alloc_reg(
								v0.data.insn_d),
							get_alloc_reg(
								v1.data.insn_d),
							insn->alu,
							jmp_code(insn->op));
					} else if (t1 == CONST) {
						extra->translated
							[0] = cond_jmp_imm(
							get_alloc_reg(
								v0.data.insn_d),
							v1.data.constant_d,
							insn->alu,
							jmp_code(insn->op));
					} else {
						CRITICAL("Error");
					}
				} else {
					DBGASSERT(t0 == CONST);
					DBGASSERT(t1 == REG);
					extra->translated[0] = cond_jmp_imm(
						get_alloc_reg(v1.data.insn_d),
						v0.data.constant_d, insn->alu,
						jmp_code(insn->op));
				}
			} else {
				CRITICAL("No such instruction");
			}
		}
	}
}

// Interface Implementation

int bpf_ir_code_gen(struct ir_function *fun)
{
	// Preparation

	// Step 1: Flag all raw stack access
	add_stack_offset_pre_cg(fun);
	bpf_ir_prog_check(fun);

	// Step 2: Eliminate SSA
	to_cssa(fun);
	bpf_ir_prog_check(fun);

	print_ir_prog_pre_cg(fun, "To CSSA");

	// Init CG, start real code generation
	init_cg(fun);

	// Debugging settings
	fun->cg_info.spill_callee = 0;

	// Step 3: Use explicit real registers
	explicit_reg(fun); // Still in SSA form, users are available
	print_ir_prog_cg_dst(fun, "Explicit REG");

	// Step 4: SSA Destruction
	// users not available from now on
	remove_phi(fun);
	print_ir_prog_cg_dst(fun, "PHI Removal");

	// print_ir_prog_reachable(fun);

	int need_spill = 1;
	int iterations = 0;

	while (need_spill) {
		iterations++;
		// Step 5: Liveness Analysis
		liveness_analysis(fun);

		// Step 6: Conflict Analysis
		conflict_analysis(fun);
		PRINT_LOG("Conflicting graph:\n");
		bpf_ir_print_interference_graph(fun);

		// Step 7: Graph coloring
		graph_coloring(fun);
		coaleasing(fun);
		PRINT_LOG("Conflicting graph (after coloring):\n");
		bpf_ir_print_interference_graph(fun);
		print_ir_prog_cg_alloc(fun, "After RA");

		// Step 8: Check if need to spill and spill
		need_spill = check_need_spill(fun);
		// print_ir_prog_cg_dst(fun, "After Spilling");
		if (need_spill) {
			// Still need to spill
			PRINT_LOG("Need to spill...\n");
			clean_cg(fun);
		}
	}

	// Register allocation finished (All registers are fixed)
	PRINT_LOG("Register allocation finished in %d iteratinos\n",
		  iterations);
	print_ir_prog_cg_alloc(fun, "After RA & Spilling");

	// Step 9: Calculate stack size
	if (fun->cg_info.spill_callee) {
		calc_callee_num(fun);
	}
	calc_stack_size(fun);

	// Step 10: Shift raw stack operations
	add_stack_offset(fun, fun->cg_info.stack_offset);
	print_ir_prog_cg_alloc(fun, "Shifting stack access");

	// Step 11: Spill callee saved registers
	if (fun->cg_info.spill_callee) {
		spill_callee(fun);
		print_ir_prog_cg_alloc(fun, "Spilling callee-saved regs");
	}

	// Step 12: Normalize
	normalize(fun);
	print_ir_prog_cg_alloc(fun, "Normalization");

	// Step 13: Direct Translation
	// translate(fun);

	// Step 14: Relocation
	// relocate(fun);

	// Step 15: Synthesize
	// synthesize(fun);

	// Free CG resources
	free_cg_res(fun);
	return 0;
}

int bpf_ir_init_insn_cg(struct ir_insn *insn)
{
	struct ir_insn_cg_extra *extra = NULL;
	SAFE_MALLOC(extra, sizeof(struct ir_insn_cg_extra));
	// When init, the destination is itself
	if (is_void(insn)) {
		extra->dst = NULL;
	} else {
		extra->dst = insn;
	}
	INIT_ARRAY(&extra->adj, struct ir_insn *);
	extra->allocated = 0;
	extra->spilled = 0;
	extra->alloc_reg = 0;
	INIT_ARRAY(&extra->gen, struct ir_insn *);
	INIT_ARRAY(&extra->kill, struct ir_insn *);
	INIT_ARRAY(&extra->in, struct ir_insn *);
	INIT_ARRAY(&extra->out, struct ir_insn *);
	extra->translated_num = 0;
	insn->user_data = extra;
	return 0;
}
