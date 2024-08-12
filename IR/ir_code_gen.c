#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "list.h"
#include "prog_check.h"
#include "ir_helper.h"

void init_cg(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = __malloc(sizeof(struct ir_bb_cg_extra));
        bb_cg->gen                   = INIT_ARRAY(struct ir_insn *);
        bb_cg->kill                  = INIT_ARRAY(struct ir_insn *);
        bb_cg->in                    = INIT_ARRAY(struct ir_insn *);
        bb_cg->out                   = INIT_ARRAY(struct ir_insn *);

        bb->user_data = bb_cg;

        struct ir_insn *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *extra = __malloc(sizeof(struct ir_insn_cg_extra));
            // When init, the destination is itself
            extra->dst = insn;
            // if (insn->users.num_elem > 0) {
            //     extra->dst = insn;
            // } else {
            //     extra->dst = NULL;
            // }
            extra->adj            = INIT_ARRAY(struct ir_insn *);
            extra->allocated      = 0;
            extra->spilled        = 0;
            extra->alloc_reg      = 0;
            extra->translated_num = 0;
            insn->user_data       = extra;
        }
    }
}

void free_cg_res(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = bb->user_data;
        array_free(&bb_cg->gen);
        array_free(&bb_cg->kill);
        array_free(&bb_cg->in);
        array_free(&bb_cg->out);
        __free(bb->user_data);
        bb->user_data = NULL;
        struct ir_insn *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *insn_cg = insn->user_data;
            array_free(&insn_cg->adj);
            __free(insn_cg);
            insn->user_data = NULL;
        }
    }
}

struct ir_insn_cg_extra *insn_cg(struct ir_insn *insn) {
    return insn->user_data;
}

struct ir_insn *dst(struct ir_insn *insn) {
    return insn_cg(insn)->dst;
}

void print_ir_prog_cg(struct ir_function *fun) {
    printf("-----------------\n");
    print_ir_prog_advanced(fun, NULL, NULL);
}

void code_gen(struct ir_function *fun) {
    // Preparation

    // Step 1: Check program
    prog_check(fun);
    // Step 2: Eliminate SSA
    to_cssa(fun);
    print_ir_prog_cg(fun);

    // Init CG, start real code generation
    // No "users" available after this step
    init_cg(fun);
    flatten(fun);

    remove_phi(fun);

    // Step 3: Liveness Analysis
    liveness_analysis(fun);

    // Step 4: Conflict Analysis
    conflict_analysis(fun);
    print_interference_graph(fun);
    printf("-------------\n");

    // Step 5: Graph coloring
    graph_coloring(fun);
    print_interference_graph(fun);
    print_ir_prog_advanced(fun, NULL, print_ir_alloc);

    // Register allocation finished

    // Step 6: Direct Translation

    // Free CG resources
    free_cg_res(fun);
}
