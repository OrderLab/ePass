#ifndef __BPF_IR_PASSES_H__
#define __BPF_IR_PASSES_H__

#include "phi_pass.h"
#include "reachable_bb.h"

/**
    All function passes.
 */
static void (*passes[])(struct ir_function *fun) = {
    gen_reachable_bbs,
    // remove_trivial_phi,
};

#endif
