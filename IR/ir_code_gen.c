#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_insn.h"
#include "list.h"
#include "prog_check.h"
#include "ir_helper.h"

void init_cg(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = __malloc(sizeof(struct ir_bb_cg_extra));
        // Empty bb cg
        bb->user_data = bb_cg;

        struct ir_insn *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *extra = __malloc(sizeof(struct ir_insn_cg_extra));
            // When init, the destination is itself
            if (is_void(insn)) {
                extra->dst = NULL;
            } else {
                extra->dst = insn;
            }
            extra->adj        = INIT_ARRAY(struct ir_insn *);
            extra->allocated  = 0;
            extra->spilled    = 0;
            extra->alloc_reg  = 0;
            extra->translated = INIT_ARRAY(struct pre_ir_insn);
            extra->gen        = INIT_ARRAY(struct ir_insn *);
            extra->kill       = INIT_ARRAY(struct ir_insn *);
            extra->in         = INIT_ARRAY(struct ir_insn *);
            extra->out        = INIT_ARRAY(struct ir_insn *);
            insn->user_data   = extra;
        }
    }
}

void free_cg_res(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = bb->user_data;
        __free(bb_cg);
        bb->user_data = NULL;
        struct ir_insn *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *insn_cg = insn->user_data;
            array_free(&insn_cg->adj);
            array_free(&insn_cg->translated);
            array_free(&insn_cg->gen);
            array_free(&insn_cg->kill);
            array_free(&insn_cg->in);
            array_free(&insn_cg->out);
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
    print_ir_prog_advanced(fun, NULL, NULL, NULL);
}

void code_gen(struct ir_function *fun) {
    // Preparation

    // Step 1: Check program
    prog_check(fun);
    // Step 2: Eliminate SSA
    to_cssa(fun);
    print_ir_prog_cg(fun);

    // Init CG, start real code generation
    init_cg(fun);
    explicit_reg(fun);

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
    print_ir_prog_advanced(fun, NULL, NULL, print_ir_alloc);

    // Register allocation finished

    // Step 6: Direct Translation

    // Free CG resources
    free_cg_res(fun);
}
