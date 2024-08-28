#include "bpf_ir.h"

void gen_end_bbs(struct ir_function *fun)
{
	struct ir_basic_block **pos;
	bpf_ir_array_clear(&fun->end_bbs);
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		if (bb->succs.num_elem == 0) {
			bpf_ir_array_push(&fun->end_bbs, &bb);
		}
	}
}
