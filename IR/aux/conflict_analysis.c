#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_helper.h"

int is_final(struct ir_insn *v1) {
    return v1 == dst(v1);
}

void build_conflict(struct ir_insn *v1, struct ir_insn *v2) {
    if (!is_final(v1) || !is_final(v2)) {
        CRITICAL("Can only build conflict on final values");
    }
    array_push_unique(&insn_cg(v1)->adj, &v2);
    array_push_unique(&insn_cg(v2)->adj, &v1);
}

void print_interference_graph(struct ir_function *fun) {
    // Tag the IR to have the actual number to print
    tag_ir(fun);
    struct ir_insn **pos;
    printf("Interference Graph:\n");
    array_for(pos, fun->cg_info.all_var) {
        struct ir_insn *insn = *pos;
        if (!is_final(insn)) {
            // Not final value, give up
            CRITICAL("Not Final Value!");
        }
        printf("%zu: ", insn->_insn_id);
        struct ir_insn **pos2;
        array_for(pos2, insn_cg(insn)->adj) {
            struct ir_insn *adj_insn = *pos2;
            if (!is_final(insn)) {
                // Not final value, give up
                CRITICAL("Not Final Value!");
            }
            printf("%zu, ", adj_insn->_insn_id);
        }
        printf("\n");
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
            struct ir_insn *insn_dst = dst(*pos2);
            // Add the variable to the "all variable set"
            array_push_unique(&fun->cg_info.all_var, &insn_dst);
        }
        array_for(pos2, bb_cg->kill) {
            struct ir_insn *insn_dst = dst(*pos2);
            array_push_unique(&fun->cg_info.all_var, &insn_dst);
            struct ir_insn **pos3;
            array_for(pos3, bb_cg->out) {
                build_conflict(insn_dst, dst(*pos3));
            }
        }
    }
}
