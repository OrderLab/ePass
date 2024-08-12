// Flatten the IR to better work with RA

#include "code_gen.h"

void flatten(struct ir_function *fun) {
    // fun is still in IR form
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *extra = insn_cg(insn);
            if (insn->op == IR_INSN_CALL) {
                if (insn->users.num_elem == 0) {
                    // Call instructions, no destination if no users (but still execute)
                    extra->dst = NULL;
                }
            }
        }
    }
}