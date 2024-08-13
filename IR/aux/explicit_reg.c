// Make register usage explicit
// Example:
// %x = add %y, %arg1
// arg1 is r0 at the beginning of the function
// We then add a new instruction to the beginning of the function.

#include "code_gen.h"

void explicit_reg(struct ir_function *fun) {
    // fun is still in IR form
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *extra = insn_cg(insn);
            if (insn->op == IR_INSN_CALL) {
                // TODO
            }
        }
    }
}
