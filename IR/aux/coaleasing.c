#include "bpf_ir.h"
#include "dbg.h"
#include "list.h"

void coaleasing(struct ir_function *fun)
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
			struct ir_insn *insn_dst = dst(pos2);
			if (pos2->op == IR_INSN_ASSIGN) {
				if (pos2->values[0].type == IR_VALUE_INSN) {
					struct ir_insn *src =
						pos2->values[0].data.insn_d;
					DBGASSERT(src == dst(src));
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
