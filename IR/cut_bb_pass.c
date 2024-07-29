#include "cut_bb_pass.h"
#include "array.h"
#include "bpf_ir.h"
#include "dbg.h"
#include "list.h"

void cut_bb(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
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
            array_for(pos2, bb->preds) {
                struct ir_basic_block  *pred = *pos2;
                struct ir_basic_block **pos3;
                array_for(pos3, pred->succs) {
                    struct ir_basic_block *succ = *pos3;
                    if (succ == bb) {
                        *pos3 = ((struct ir_basic_block **)(bb->succs.data))[0];
                    }
                }
            }
        }
    }
}
