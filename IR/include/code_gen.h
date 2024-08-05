#ifndef __BPF_IR_CODE_GEN_H__
#define __BPF_IR_CODE_GEN_H__

#include "ir_fun.h"

// Extra information needed for code generation for each basic block
struct ir_bb_cg_extra {
    struct array in;
    struct array out;
    struct array gen;
    struct array kill;
    struct array def;
};

void code_gen(struct ir_function *fun);

// For debugging
void liveness_analysis(struct ir_function *fun);

#endif
