#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"

void build_conflict(struct ir_insn *v1, struct ir_insn *v2) {
    if (v1 != dst(v1) || v2 != dst(v2)) {
        CRITICAL("Can only build conflict on final values");
    }
    array_push_unique(&insn_cg(v1)->adj, &v2);
    array_push_unique(&insn_cg(v2)->adj, &v1);
}

void print_interference_graph(struct ir_function *fun) {
    struct ir_insn **pos;
    printf("Interference Graph:\n");
    array_for(pos, fun->cg_info.all_var){

    }
}

void conflict_analysis(struct ir_function *fun) {
    // Basic conflict:
    // For every x in KILL set, x is conflict with every element in OUT set.

    struct ir_basic_block **pos;
    // For each BB
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = bb->user_data;
        struct ir_insn       **pos2;
        array_for(pos2, bb_cg->out) {
            // Add the variable to the "all variable set"
            array_push_unique(&fun->cg_info.all_var, pos2);
        }
        array_for(pos2, bb_cg->kill) {
            array_push_unique(&fun->cg_info.all_var, pos2);
            struct ir_insn **pos3;
            array_for(pos3, bb_cg->out) {
                build_conflict(dst(*pos2), dst(*pos3));
            }
        }
    }
}
