#ifndef __BPF_IR_PASSES_H__
#define __BPF_IR_PASSES_H__

#include "ir_fun.h"

void remove_trivial_phi(struct ir_function *fun);

void cut_bb(struct ir_function *fun);

void add_counter(struct ir_function *fun);

void add_constraint(struct ir_function *fun);

void gen_reachable_bbs(struct ir_function *);

void gen_end_bbs(struct ir_function *fun);

struct function_pass {
    void (*pass)(struct ir_function *);
    char name[30];
};

#define DEF_FUNC_PASS(fun, msg) {.pass = fun, .name = msg}

/**
    All function passes.
 */
static const struct function_pass passes[] = {
    DEF_FUNC_PASS(remove_trivial_phi, "Remove the trival Phi"),
    DEF_FUNC_PASS(add_counter, "Adding counter"),
};

#endif
