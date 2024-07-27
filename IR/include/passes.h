#ifndef __BPF_IR_PASSES_H__
#define __BPF_IR_PASSES_H__

#include "add_constraint_pass.h"
#include "phi_pass.h"
#include "add_counter_pass.h"
#include "ir_fun.h"

/**
    All function passes.
 */
static void (*passes[])(struct ir_function *fun) = {
    remove_trivial_phi,
    // add_constraint,
    // add_counter,
};

#endif
