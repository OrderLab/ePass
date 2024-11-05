// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

// Pre CG
void bpf_ir_cg_change_fun_arg(struct bpf_ir_env *env, struct ir_function *fun,
			      void *param)
{
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		if (fun->function_arg[i]->users.num_elem > 0) {
			// Insert ASSIGN arg[i] at the beginning of the function
			struct ir_insn *new_insn = bpf_ir_create_assign_insn_bb(
				env, fun->entry,
				bpf_ir_value_insn(fun->cg_info.regs[i + 1]),
				INSERT_FRONT_AFTER_PHI);
			bpf_ir_replace_all_usage(env, fun->function_arg[i],
						 bpf_ir_value_insn(new_insn));
		}
	}
}

// Pre CG
void bpf_ir_cg_change_call_pre_cg(struct bpf_ir_env *env,
				  struct ir_function *fun, void *param)
{
	// Change function call args
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_CALL) {
				if (insn->users.num_elem == 0) {
					continue;
				}
				struct ir_insn *new_insn =
					bpf_ir_create_assign_insn(
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

// Pre CG
void bpf_ir_cg_add_stack_offset_pre_cg(struct bpf_ir_env *env,
				       struct ir_function *fun, void *param)
{
	struct array users = fun->sp->users;
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
		if (bpf_ir_is_bin_alu(insn) &&
		    insn->values[0].type == IR_VALUE_INSN &&
		    insn->values[0].data.insn_d == fun->sp &&
		    insn->values[1].type == IR_VALUE_CONSTANT) {
			// ? = ALU SP CONST
			insn->values[1].type = IR_VALUE_CONSTANT_RAWOFF;
			continue;
		}
		struct array value_uses = bpf_ir_get_operands(env, insn);
		struct ir_value **pos2;
		array_for(pos2, value_uses)
		{
			struct ir_value *val = *pos2;
			if (val->type == IR_VALUE_INSN &&
			    val->data.insn_d == fun->sp && !val->raw_stack) {
				// Stack pointer as value
				// tmp = SP + hole(0)
				// ... val ==> tmp
				struct ir_insn *new_insn =
					bpf_ir_create_bin_insn(
						env, insn, *val,
						bpf_ir_value_const32_rawoff(0),
						IR_INSN_ADD, IR_ALU_64,
						INSERT_FRONT);
				bpf_ir_change_value(
					env, insn, val,
					bpf_ir_value_insn(new_insn));
			}
		}
		bpf_ir_array_free(&value_uses);
	}
}

// Convert from TSSA to CSSA
// Using "Method I" in paper "Translating Out of Static Single Assignment Form"
void bpr_ir_cg_to_cssa(struct bpf_ir_env *env, struct ir_function *fun,
		       void *param)
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
		// Create the moved PHI insn
		struct ir_insn *new_phi = bpf_ir_create_phi_insn_bb(
			env, insn->parent_bb, INSERT_FRONT);
		struct phi_value *pos3;
		array_for(pos3, insn->phi)
		{
			struct ir_insn *new_insn = bpf_ir_create_assign_insn_bb(
				env, pos3->bb, pos3->value,
				INSERT_BACK_BEFORE_JMP);
			// Remove use
			bpf_ir_val_remove_user(pos3->value, insn);
			bpf_ir_phi_add_operand(env, new_phi, pos3->bb,
					       bpf_ir_value_insn(new_insn));
		}

		bpf_ir_array_free(&insn->phi);
		insn->op = IR_INSN_ASSIGN;
		struct ir_value val = bpf_ir_value_insn(new_phi);
		insn->values[0] = val;
		insn->value_num = 1;
		bpf_ir_val_add_user(env, val, insn);
	}

	bpf_ir_array_free(&phi_insns);
}
