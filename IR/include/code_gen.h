#ifndef __BPF_IR_CODE_GEN_H__
#define __BPF_IR_CODE_GEN_H__

#include "ir_fun.h"

void code_gen(struct ir_function *fun);

// For debugging
void liveness_analysis(struct ir_function *fun);

// Extra information needed for liveness analysis
struct ir_bb_la_extra {
    struct array in;
    struct array out;
    struct array gen;
    struct array kill;
    struct array def;
};

void elim_ssa(struct ir_function *fun);

#endif
