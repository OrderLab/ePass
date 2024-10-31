// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

static void check_insn_users_use_insn(struct bpf_ir_env *env,
				      struct ir_insn *insn)
{
	struct ir_insn **pos;
	array_for(pos, insn->users)
	{
		struct ir_insn *user = *pos;
		// Check if the user actually uses this instruction
		struct array operands = bpf_ir_get_operands(env, user);
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
			print_ir_insn_err(env, insn, "The instruction");
			print_ir_insn_err(env, user,
					  "The user of that instruction");
			RAISE_ERROR("User does not use the instruction");
		}
	}
}

static void check_insn(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Check syntax
	// Check value num
	// - Store uses alloc
	// - Load uses alloc
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->parent_bb != bb) {
				print_ir_insn_err(
					env, insn,
					"Instruction's parent BB wrong");
				RAISE_ERROR("Parent BB error");
			}
			if (insn->op == IR_INSN_LOADRAW ||
			    insn->op == IR_INSN_ALLOC ||
			    insn->op == IR_INSN_JA || insn->op == IR_INSN_PHI ||
			    insn->op == IR_INSN_ALLOCARRAY ||
			    insn->op == IR_INSN_THROW) {
				if (!(insn->value_num == 0)) {
					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR(
						"Instruction should have no value");
				}
			}
			if (insn->op == IR_INSN_STORERAW ||
			    insn->op == IR_INSN_LOAD ||
			    insn->op == IR_INSN_RET ||
			    insn->op == IR_INSN_NEG ||
			    insn->op == IR_INSN_HTOBE ||
			    insn->op == IR_INSN_HTOLE) {
				if (!(insn->value_num == 1)) {
					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR(
						"Instruction should have 1 values");
				}
			}

			if (insn->op == IR_INSN_HTOBE ||
			    insn->op == IR_INSN_HTOLE) {
				if (!(insn->swap_width == 16 ||
				      insn->swap_width == 32 ||
				      insn->swap_width == 64)) {
					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR(
						"BPF_END instruction must have a valid swap width (16, 32 or 64)");
				}
			}

			if (insn->op == IR_INSN_STORE ||
			    (bpf_ir_is_bin_alu(insn)) ||
			    (bpf_ir_is_cond_jmp(insn)) ||
			    insn->op == IR_INSN_GETELEMPTR) {
				if (!(insn->value_num == 2)) {
					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR(
						"Instruction should have 2 values");
				}
			}

			if (insn->op == IR_INSN_STORE ||
			    insn->op == IR_INSN_LOAD) {
				if (!(insn->values[0].type == IR_VALUE_INSN &&
				      insn->values[0].data.insn_d->op ==
					      IR_INSN_ALLOC)) {
					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR(
						"Value[0] should be an alloc instruction");
				}
			}

			if (insn->op == IR_INSN_GETELEMPTR) {
				if (!(insn->values[1].type == IR_VALUE_INSN &&
				      insn->values[1].data.insn_d->op ==
					      IR_INSN_ALLOCARRAY)) {
					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR(
						"Value should be an allocarray instruction");
				}
			}

			// TODO: Check: users of alloc instructions must be STORE/LOAD

			if (bpf_ir_is_bin_alu(insn) ||
			    bpf_ir_is_cond_jmp(insn)) {
				// Binary ALU
				if (!bpf_ir_valid_alu_type(insn->alu_op)) {
					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR("Binary ALU type error!");
				}
			}

			struct array operands = bpf_ir_get_operands(env, insn);
			struct ir_value **vpos;
			if (insn->op == IR_INSN_ALLOC ||
			    insn->op == IR_INSN_LOADRAW ||
			    insn->op == IR_INSN_STORERAW) {
				if (!bpf_ir_valid_vr_type(insn->vr_type)) {
					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR("Invalid VR type");
				}
			}

			// Checking operands
			array_for(vpos, operands)
			{
				struct ir_value *val = *vpos;
				if (val->type == IR_VALUE_CONSTANT) {
					if (!bpf_ir_valid_alu_type(
						    val->const_type)) {
						print_ir_insn_err(env, insn,
								  NULL);

						PRINT_LOG_DEBUG(
							env,
							"Constant type: %d, operand number: %d\n",
							val->const_type,
							operands.num_elem);
						RAISE_ERROR(
							"Invalid Constant type");
					}
				}
			}
			bpf_ir_array_free(&operands);
		}
	}
}

static void check_insn_operand(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct array operands = bpf_ir_get_operands(env, insn);
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
				print_ir_insn_err(env, v->data.insn_d,
						  "Operand defined here");
				print_ir_insn_err(
					env, insn,
					"Instruction that uses the operand");
				RAISE_ERROR(
					"Instruction not found in the operand's users");
			}
		}
	}
	bpf_ir_array_free(&operands);
}

// Check if the users are correct (only applicable to SSA IR form)
static void check_users(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Check FunctionCallArgument Instructions
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		struct ir_insn *insn = fun->function_arg[i];
		check_insn_users_use_insn(env, insn);
	}
	check_insn_users_use_insn(env, fun->sp);
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			// Check users of this instruction
			check_insn_users_use_insn(env, insn);
			// Check operands of this instruction
			check_insn_operand(env, insn);
		}
	}
}

static void check_jumping(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Check if the jump instruction is at the end of the BB
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;

		// check if BB is a succ of its preds
		struct ir_basic_block **pred;
		array_for(pred, bb->preds)
		{
			struct ir_basic_block *pred_bb = *pred;
			struct ir_basic_block **succ;
			int found = 0;
			array_for(succ, pred_bb->succs)
			{
				struct ir_basic_block *succ_bb = *succ;
				if (succ_bb == bb) {
					found = 1;
					break;
				}
			}
			if (!found) {
				// Error
				print_ir_bb_err(env, bb);
				PRINT_LOG_ERROR(env, "Pred: %zu\n",
						pred_bb->_id);
				RAISE_ERROR("BB not a succ of its pred");
			}
		}

		struct ir_basic_block **succ;
		array_for(succ, bb->succs)
		{
			struct ir_basic_block *succ_bb = *succ;
			struct ir_basic_block **p;
			int found = 0;
			array_for(p, succ_bb->preds)
			{
				struct ir_basic_block *sp = *p;
				if (sp == bb) {
					found = 1;
					break;
				}
			}
			if (!found) {
				// Error
				print_ir_bb_err(env, bb);
				RAISE_ERROR("BB not a pred of its succ");
			}
		}

		struct ir_insn *insn;
		int jmp_exists = 0;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (bpf_ir_is_jmp(insn)) {
				jmp_exists = 1;
				if (!bpf_ir_is_last_insn(insn)) {
					// Error

					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR(
						"Jump statement not at the end of a BB");
				} else {
					if (insn->op == IR_INSN_RET ||
					    insn->op == IR_INSN_THROW) {
						if (bb->succs.num_elem != 0) {
							// Error

							print_ir_insn_err(env,
									  insn,
									  NULL);
							RAISE_ERROR(
								"successor exists even after return statement");
						}
						continue;
					}
					// For conditional jumps, both BB1 and BB2 should be successors
					if (bpf_ir_is_cond_jmp(insn)) {
						// Get the two basic blocks that the conditional jump statement jumps to
						struct ir_basic_block *bb1 =
							insn->bb1;
						struct ir_basic_block *bb2 =
							insn->bb2;
						// Check if the two basic blocks are successors of the current BB
						if (bb->succs.num_elem != 2) {
							RAISE_ERROR(
								"BB succs error");
						}
						if (*array_get(
							    &bb->succs, 0,
							    struct ir_basic_block
								    *) != bb1 ||
						    *array_get(
							    &bb->succs, 1,
							    struct ir_basic_block
								    *) != bb2) {
							// Error
							RAISE_ERROR(
								"Conditional jump statement with operands that are not successors "
								"of the current BB");
						}
					} else {
						// For unconditional jumps, there should be only one successor
						if (bb->succs.num_elem != 1) {
							// Error

							print_ir_insn_err(env,
									  insn,
									  NULL);
							RAISE_ERROR(
								"Unconditional jump statement with more than one successor");
						}
						// Check if the jump operand is the only successor of BB
						if (*array_get(
							    &bb->succs, 0,
							    struct ir_basic_block
								    *) !=
						    insn->bb1) {
							// Error

							print_ir_insn_err(env,
									  insn,
									  NULL);
							RAISE_ERROR(
								"The jump operand is not the only successor of BB");
						}
					}
				}
			}
		}
		// If there is no jump instruction (means no ret), there should be one successor
		if (!jmp_exists) {
			if (bb->succs.num_elem != 1) {
				// Error
				print_ir_bb_err(env, bb);
				RAISE_ERROR("Succ num error");
			}
		}
	}
}

// Check if the PHI nodes are at the beginning of the BB
static void check_phi(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		int all_phi = 1;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_PHI) {
				if (!all_phi) {
					// Error!
					print_ir_insn_err(env, insn, NULL);
					RAISE_ERROR(
						"Phi node not at the beginning of a BB");
				}
			} else {
				all_phi = 0;
			}
		}
	}
}

static void bpf_ir_fix_bb_succ(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->all_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = bpf_ir_get_last_insn(bb);
		if (insn && bpf_ir_is_cond_jmp(insn)) {
			// Conditional jmp
			if (bb->succs.num_elem != 2) {
				print_ir_insn_err(env, insn,
						  "Jump instruction");
				RAISE_ERROR(
					"Conditional jmp with != 2 successors");
			}
			struct ir_basic_block **s1 = array_get(
				&bb->succs, 0, struct ir_basic_block *);
			struct ir_basic_block **s2 = array_get(
				&bb->succs, 1, struct ir_basic_block *);
			*s1 = insn->bb1;
			*s2 = insn->bb2;
		}
	}
}

static void add_reach(struct bpf_ir_env *env, struct ir_function *fun,
		      struct ir_basic_block *bb)
{
	if (bb->_visited) {
		return;
	}
	bb->_visited = 1;
	bpf_ir_array_push(env, &fun->reachable_bbs, &bb);

	struct ir_basic_block **succ;
	bool first = false;
	array_for(succ, bb->succs)
	{
		if (!first && bb->succs.num_elem > 1) {
			first = true;
			// Check if visited
			if ((*succ)->_visited) {
				RAISE_ERROR("Loop BB detected");
			}
		}
		add_reach(env, fun, *succ);
	}
}

static void gen_reachable_bbs(struct bpf_ir_env *env, struct ir_function *fun)
{
	bpf_ir_clean_visited(fun);
	bpf_ir_array_clear(env, &fun->reachable_bbs);
	add_reach(env, fun, fun->entry);
}

static void gen_end_bbs(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	bpf_ir_array_clear(env, &fun->end_bbs);
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		if (bb->succs.num_elem == 0) {
			bpf_ir_array_push(env, &fun->end_bbs, &bb);
		}
	}
}

// Interface Implementation

static void check_err_and_print(struct bpf_ir_env *env, struct ir_function *fun)
{
	if (env->err) {
		PRINT_LOG_DEBUG(env, "----- DUMP IR START -----\n");
		print_ir_prog_notag(env, fun);
		PRINT_LOG_DEBUG(env, "----- DUMP IR END -----\n");
	}
}

#define CHECK_DUMP()                   \
	check_err_and_print(env, fun); \
	CHECK_ERR();

// Check that the program is valid and able to be compiled
void bpf_ir_prog_check(struct bpf_ir_env *env, struct ir_function *fun)
{
	print_ir_err_init(fun);

	bpf_ir_fix_bb_succ(env, fun);
	CHECK_DUMP();

	bpf_ir_clean_metadata_all(fun);
	gen_reachable_bbs(env, fun);
	CHECK_DUMP();
	gen_end_bbs(env, fun);
	CHECK_DUMP();

	check_insn(env, fun);
	CHECK_DUMP();

	check_phi(env, fun);
	CHECK_DUMP();

	check_users(env, fun);
	CHECK_DUMP();

	check_jumping(env, fun);
}
