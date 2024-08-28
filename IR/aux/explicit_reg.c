// Make register usage explicit
// Example:
// %x = add %y, %arg1
// arg1 is r0 at the beginning of the function
// We then add a new instruction to the beginning of the function.

#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_insn.h"
#include "ir_helper.h"

void explicit_reg(struct ir_function *fun)
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
					ir_value_insn(fun->cg_info.regs[0]),
					INSERT_BACK);
				replace_all_usage(insn,
						  ir_value_insn(new_insn));
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
				ir_value_insn(fun->cg_info.regs[i + 1]),
				INSERT_FRONT_AFTER_PHI);
			replace_all_usage(fun->function_arg[i],
					  ir_value_insn(new_insn));
		}
	}
}
