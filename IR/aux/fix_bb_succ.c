#include "bpf_ir.h"

void bpf_ir_fix_bb_succ(struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->all_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = bpf_ir_get_last_insn(bb);
		if (insn && is_cond_jmp(insn)) {
			// Conditional jmp
			if (bb->succs.num_elem != 2) {
				CRITICAL(
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
