
#include "array.h"
#include "reachable_bb.h"

void add_reach(struct ir_function *fun, struct ir_basic_block *bb) {
    if (bb->_visited) {
        return;
    }
    bb->_visited = 1;
    array_push(&fun->reachable_bbs, &bb);

    struct ir_basic_block **succ;
    array_for(succ, bb->succs) {
        add_reach(fun, *succ);
    }
}

void gen_reachable_bbs(struct ir_function *fun) {
    fun->reachable_bbs = array_init(sizeof(struct ir_basic_block *));
    add_reach(fun, fun->entry);
}
