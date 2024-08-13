#ifndef __BPF_IR_FUN_H__
#define __BPF_IR_FUN_H__

#include "bpf_ir.h"

struct code_gen_info {
    // All vertex in interference graph
    // Array of struct ir_insn*
    struct array all_var;

    // BPF Register Virtual Instruction (used as dst)
    struct ir_insn regs[__MAX_BPF_REG];
};

struct ir_function {
    size_t arg_num;

    // Array of struct pre_ir_basic_block *, no entrance information anymore
    struct array all_bbs;

    // The entry block
    struct ir_basic_block *entry;

    // Store any information about the function
    struct array reachable_bbs;

    // Stack pointer (r10) users. Should be readonly. No more manual stack access should be allowed.
    struct array sp_users;

    // Array of struct ir_constraint. Value constraints.
    struct array value_constraints;

    struct code_gen_info cg_info;
};

// Constructor and Destructor

struct ir_function gen_function(struct ssa_transform_env *env);

void free_function(struct ir_function *fun);

#endif
