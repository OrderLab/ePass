// Relocate BB
#include "bpf_ir.h"

void calc_pos(struct ir_function *fun)
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

void relocate(struct ir_function *fun)
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
				size_t target = bb_cg(insn->bb1)->pos;
				insn_extra->translated[0].off =
					target - insn_extra->translated[0].pos -
					1;
			}
			if (is_cond_jmp(insn)) {
				DBGASSERT(insn_extra->translated_num == 1);
				size_t target = bb_cg(insn->bb2)->pos;
				insn_extra->translated[0].off =
					target - insn_extra->translated[0].pos -
					1;
			}
		}
	}
}
