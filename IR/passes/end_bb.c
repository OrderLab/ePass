#include "array.h"
#include "ir_fun.h"

void gen_end_bbs(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        if (bb->succs.num_elem == 0) {
            array_push(&fun->end_bbs, &bb);
        }
    }
}
