#ifndef __BPF_IR_PASSES_H__
#define __BPF_IR_PASSES_H__

#include "ir_fun.h"

void remove_trivial_phi(struct ir_function *fun);

void cut_bb(struct ir_function *fun);

void add_counter(struct ir_function *fun);

void add_constraint(struct ir_function *fun);

void gen_reachable_bbs(struct ir_function *);

void gen_end_bbs(struct ir_function *fun);

/**
    All function passes.
 */
static void (*passes[])(struct ir_function *fun) = {
    remove_trivial_phi,
    gen_end_bbs,
    // add_constraint,
    add_counter,
};

#endif
