#include "bpf_ir.h"

void add_reach(struct ir_function *fun, struct ir_basic_block *bb)
{
	if (bb->_visited) {
		return;
	}
	bb->_visited = 1;
	array_push(&fun->reachable_bbs, &bb);

	struct ir_basic_block **succ;
	__u8 i = 0;
	array_for(succ, bb->succs)
	{
		if (i == 0) {
			i = 1;
			// Check if visited
			if ((*succ)->_visited) {
				CRITICAL("Loop BB detected");
			}
		}
		add_reach(fun, *succ);
	}
}

void gen_reachable_bbs(struct ir_function *fun)
{
	clean_env(fun);
	array_clear(&fun->reachable_bbs);
	add_reach(fun, fun->entry);
}
