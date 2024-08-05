#include "code_gen.h"
#include "prog_check.h"

void init_bb_info(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = __malloc(sizeof(struct ir_bb_cg_extra));
        bb_cg->gen                   = INIT_ARRAY(struct ir_instr *);
        bb_cg->kill                  = INIT_ARRAY(struct ir_instr *);
        bb_cg->in                    = INIT_ARRAY(struct ir_instr *);
        bb_cg->out                   = INIT_ARRAY(struct ir_instr *);
        bb->user_data                = bb_cg;
    }
}

void free_bb_info(struct ir_function *fun) {
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
    }
}

void code_gen(struct ir_function *fun){
    // Init
    init_bb_info(fun);
    // Step 1: Check program
    prog_check(fun);
    // Step 2: Eliminate SSA
    elim_ssa(fun);

    // Free resource
    free_bb_info(fun);
}