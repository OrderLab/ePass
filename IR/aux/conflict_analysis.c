#include <linux/bpf.h>

#include "bpf_ir.h"

int is_final(struct ir_insn *v1)
{
	return v1 == dst(v1);
}

void build_conflict(struct ir_insn *v1, struct ir_insn *v2)
{
	if (!is_final(v1) || !is_final(v2)) {
		CRITICAL("Can only build conflict on final values");
	}
	if (v1 == v2) {
		return;
	}
	array_push_unique(&insn_cg(v1)->adj, &v2);
	array_push_unique(&insn_cg(v2)->adj, &v1);
}

void print_interference_graph(struct ir_function *fun)
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
		if (!is_final(insn)) {
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
			if (!is_final(adj_insn)) {
				// Not final value, give up
				CRITICAL("Not Final Value!");
			}
			PRINT_LOG(" ");
			print_insn_ptr_base(adj_insn);
		}
		PRINT_LOG("\n");
	}
}

void caller_constraint(struct ir_function *fun, struct ir_insn *insn)
{
	for (__u8 i = BPF_REG_0; i < BPF_REG_6; ++i) {
		// R0-R5 are caller saved register
		DBGASSERT(fun->cg_info.regs[i] == dst(fun->cg_info.regs[i]));
		build_conflict(fun->cg_info.regs[i], insn);
	}
}

void conflict_analysis(struct ir_function *fun)
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
					DBGASSERT(*pos2 == dst(*pos2));
					struct ir_insn **pos3;
					array_for(pos3, insn_cg->out)
					{
						DBGASSERT(*pos3 == dst(*pos3));
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
				DBGASSERT(insn_dst == dst(insn_dst));
				if (insn_dst->op != IR_INSN_REG) {
					array_push_unique(&fun->cg_info.all_var,
							  &insn_dst);
				}
				struct ir_insn **pos3;
				array_for(pos3, insn_cg->out)
				{
					DBGASSERT(*pos3 == dst(*pos3));
					build_conflict(insn_dst, *pos3);
				}
			}
		}
	}
}
