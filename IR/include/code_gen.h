#ifndef __BPF_IR_CODE_GEN_H__
#define __BPF_IR_CODE_GEN_H__

#include "bpf_ir.h"
#include "ir_fun.h"

void code_gen(struct ir_function *fun);

// Extra information needed for code gen
struct ir_bb_cg_extra {
    // Liveness analysis
    struct array in;
    struct array out;
    struct array gen;
    struct array kill;
};

struct ir_insn_cg_extra {
    // Destination (Not in SSA form anymore)
    struct ir_insn *dst;

    // Adj list in interference graph
    // Array of struct ir_insn*
    struct array adj;
};

struct ir_insn_cg_extra *insn_cg(struct ir_insn *insn);

struct ir_insn *dst(struct ir_insn *insn);

void to_cssa(struct ir_function *fun);

void remove_phi(struct ir_function *fun);

void print_ir_prog_cg(struct ir_function *fun);

void liveness_analysis(struct ir_function *fun);

void conflict_analysis(struct ir_function *fun);

void print_interference_graph(struct ir_function *fun);

void graph_coloring(struct ir_function *fun);

#endif
