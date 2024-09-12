
#include <linux/bpf_ir.h>

// Warning: Not usable now
void cut_bb(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		if (list_empty(&bb->ir_insn_head)) {
			// Empty BB, try removing!
			if (bb->succs.num_elem == 0) {
				CRITICAL("Empty BB with no successors");
			}
			if (bb->succs.num_elem > 1) {
				CRITICAL("Empty BB with > 1 successors");
			}
			struct ir_basic_block **pos2;
			struct ir_basic_block *next =
				((struct ir_basic_block **)(bb->succs.data))[0];
			array_for(pos2, bb->preds)
			{
				struct ir_basic_block *pred = *pos2;
				struct ir_basic_block **pos3;
				array_for(pos3, pred->succs)
				{
					struct ir_basic_block *succ = *pos3;
					if (succ == bb) {
						*pos3 = next;
					}
				}
			}
			struct ir_insn **pos4;
			array_for(pos4, bb->users)
			{
				struct ir_insn *user = *pos4;
				if (user->bb1 == bb) {
					user->bb1 = next;
				}
				if (user->bb2 == bb) {
					user->bb2 = next;
				}
				if (user->op == IR_INSN_PHI) {
					struct phi_value *pos5;
					array_for(pos5, user->phi)
					{
						if (pos5->bb == bb) {
							pos5->bb = next;
						}
					}
				}
			}
		}
	}
}
