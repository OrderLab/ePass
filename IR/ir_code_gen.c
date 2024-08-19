#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_insn.h"
#include "list.h"
#include "prog_check.h"
#include "ir_helper.h"

struct ir_insn_cg_extra *init_insn_cg(struct ir_insn *insn) {
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
    return extra;
}

void init_cg(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = __malloc(sizeof(struct ir_bb_cg_extra));
        // Empty bb cg
        bb->user_data = bb_cg;

        struct ir_insn *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            init_insn_cg(insn);
        }
    }

    for (__u8 i = 0; i < MAX_FUNC_ARG; ++i) {
        fun->cg_info.regs[i]           = __malloc(sizeof(struct ir_insn));
        struct ir_insn *insn           = fun->cg_info.regs[i];
        insn->op                       = IR_INSN_REG;
        insn->parent_bb                = NULL;
        insn->users                    = INIT_ARRAY(struct ir_insn *);
        insn->value_num                = 0;
        struct ir_insn_cg_extra *extra = init_insn_cg(insn);
        extra->alloc_reg               = i;
        extra->dst                     = insn;
        // Pre-colored registers are allocated
        extra->allocated               = 1;
        extra->spilled                 = 0;
    }
}

void free_insn_cg(struct ir_insn *insn) {
    struct ir_insn_cg_extra *extra = insn_cg(insn);
    array_free(&extra->adj);
    array_free(&extra->translated);
    array_free(&extra->gen);
    array_free(&extra->kill);
    array_free(&extra->in);
    array_free(&extra->out);
    __free(extra);
    insn->user_data = NULL;
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
            free_insn_cg(insn);
        }
    }

    for (__u8 i = 0; i < MAX_FUNC_ARG; ++i) {
        struct ir_insn *insn = fun->cg_info.regs[i];
        array_free(&insn->users);
        free_insn_cg(insn);
        __free(insn);
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
    check_users(fun);
    print_ir_prog_cg(fun);

    // Init CG, start real code generation
    init_cg(fun);
    explicit_reg(fun);  // Still in SSA form, users are available
    print_ir_prog_cg(fun);
    printf("-----------------\n");
    print_ir_prog_advanced(fun, NULL, NULL, print_ir_dst);

    // SSA Destruction
    // users not available from now on

    remove_phi(fun);
    printf("-----------------\nPhi removed:\n");
    print_ir_prog_advanced(fun, NULL, NULL, print_ir_dst);

    // Step 3: Liveness Analysis
    liveness_analysis(fun);

    // Step 4: Conflict Analysis
    conflict_analysis(fun);
    print_interference_graph(fun);
    printf("-------------\n");

    // Step 5: Graph coloring
    graph_coloring(fun);
    coaleasing(fun);
    print_interference_graph(fun);
    print_ir_prog_advanced(fun, NULL, NULL, print_ir_alloc);

    // Register allocation finished

    // Step 6: Direct Translation

    // Free CG resources
    free_cg_res(fun);
}
