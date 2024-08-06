#include "array.h"
#include "code_gen.h"

void conflict_analysis(struct ir_function *fun) {
    // Basic conflict:
    // For every x in KILL set, x is conflict with every element in OUT set.
    
    struct ir_basic_block **pos;
    // For each BB
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = bb->user_data;
        struct ir_insn        **pos2;
        array_for(pos2, bb_cg->kill){
            array_push_unique(&fun->cg_info.all_var, pos2);
        }
    }
}
