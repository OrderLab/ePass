#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_helper.h"
#include "list.h"

int is_final(struct ir_insn *v1) {
    return v1 == dst(v1);
}

void build_conflict(struct ir_insn *v1, struct ir_insn *v2) {
    if (!is_final(v1) || !is_final(v2)) {
        CRITICAL("Can only build conflict on final values");
    }
    if (v1 == v2) {
        return;
    }
    array_push_unique(&insn_cg(v1)->adj, &v2);
    array_push_unique(&insn_cg(v2)->adj, &v1);
}

void print_interference_graph(struct ir_function *fun) {
    // Tag the IR to have the actual number to print
    tag_ir(fun);
    struct ir_insn **pos;
    array_for(pos, fun->cg_info.all_var) {
        struct ir_insn *insn = *pos;
        if (!is_final(insn)) {
            // Not final value, give up
            CRITICAL("Not Final Value!");
        }
        struct ir_insn_cg_extra *extra = insn_cg(insn);
        if (extra->allocated) {
            printf("%%%zu(", insn->_insn_id);
            if (extra->spilled) {
                printf("sp-%zu", extra->spilled * 8);
            } else {
                printf("r%u", extra->alloc_reg);
            }
            printf("): ");
        } else {
            if (insn->op == IR_INSN_REG) {
                printf("R%u: ", extra->alloc_reg);
            } else {
                printf("%%%zu: ", insn->_insn_id);
            }
        }
        struct ir_insn **pos2;
        array_for(pos2, insn_cg(insn)->adj) {
            struct ir_insn *adj_insn = *pos2;
            if (!is_final(adj_insn)) {
                // Not final value, give up
                CRITICAL("Not Final Value!");
            }
            if (adj_insn->op == IR_INSN_REG) {
                printf("R%u, ", extra->alloc_reg);
            } else {
                printf("%%%zu, ", adj_insn->_insn_id);
            }
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
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        // For each operation
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn         **pos2;
            struct ir_insn_cg_extra *insn_cg = insn->user_data;
            array_for(pos2, insn_cg->kill) {
                struct ir_insn *insn_dst = *pos2;
                DBGASSERT(insn_dst == dst(insn_dst));
                array_push_unique(&fun->cg_info.all_var, &insn_dst);
                struct ir_insn **pos3;
                array_for(pos3, insn_cg->out) {
                    DBGASSERT(*pos3 == dst(*pos3));
                    build_conflict(insn_dst, *pos3);
                }
            }
        }
    }
}
