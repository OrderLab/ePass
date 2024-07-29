// Live variable analysis
#include "array.h"
#include "code_gen.h"
#include "ir_fun.h"
#include "list.h"

void init_bb_info(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = __malloc(sizeof(struct ir_bb_cg_extra));
        bb_cg->gen                   = array_init(sizeof(struct ir_instr *));
        bb_cg->kill                  = array_init(sizeof(struct ir_instr *));
        bb_cg->in                    = array_init(sizeof(struct ir_instr *));
        bb_cg->out                   = array_init(sizeof(struct ir_instr *));
        bb->user_data                = bb_cg;
    }
}

void free_bb_info(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_bb_cg_extra *bb_cg = bb->user_data;
        array_free(&bb_cg->gen);
        array_free(&bb_cg->kill);
        array_free(&bb_cg->in);
        array_free(&bb_cg->out);
        __free(bb->user_data);
        bb->user_data = NULL;
    }
}

void liveness_analysis(struct ir_function *fun) {
    init_bb_info(fun);
    struct ir_basic_block **pos;
    // For each BB
    array_for(pos, fun->reachable_bbs){
        struct ir_basic_block *bb = *pos;
        struct ir_bb_cg_extra *bb_cg = bb->user_data;
        struct ir_insn        *pos2;
        // For each operation in reverse
        list_for_each_entry_reverse(pos2, &bb->ir_insn_head, list_ptr){
            
        }
    }
    free_bb_info(fun);
}
