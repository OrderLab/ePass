#ifndef __BPF_IR_CODE_GEN_H__
#define __BPF_IR_CODE_GEN_H__

#include "bpf_ir.h"
#include "ir_fun.h"

void code_gen(struct ir_function *fun);

// For debugging
void liveness_analysis(struct ir_function *fun);

// Extra information needed for code gen
struct ir_bb_cg_extra {
    // Liveness analysis
    struct array in;
    struct array out;
    struct array gen;
    struct array kill;
    struct array def;
};

struct ir_insn_cg_extra {
    // Destination (Not in SSA form anymore)
    struct ir_insn *dst;
};

void to_cssa(struct ir_function *fun);

void print_ir_prog_cg(struct ir_function *fun);

#endif
