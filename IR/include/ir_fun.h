#ifndef __BPF_IR_FUN_H__
#define __BPF_IR_FUN_H__

#include "bpf_ir.h"

struct code_gen_info {
    // All vertex in interference graph
    // Array of struct ir_insn*
    struct array all_var;

    // BPF Register Virtual Instruction (used as dst)
    struct ir_insn *regs[MAX_BPF_REG];

    size_t callee_num;

    __s16 stack_offset;
};

struct ir_function {
    size_t arg_num;

    // Array of struct ir_basic_block *
    struct array all_bbs;

    // The entry block
    struct ir_basic_block *entry;

    // Store any information about the function
    struct array reachable_bbs;

    // BBs who has no successors
    struct array end_bbs;

    // Stack pointer (r10) users. Should be readonly. No more manual stack access should be allowed.
    struct array sp_users;

    // Function argument
    struct ir_insn *function_arg[MAX_FUNC_ARG];

    // Array of struct ir_constraint. Value constraints.
    struct array value_constraints;

    struct code_gen_info cg_info;
};

// Constructor and Destructor

struct ir_function gen_function(struct ssa_transform_env *env);

void free_function(struct ir_function *fun);

void fix_bb_succ(struct ir_function *fun);

// IR checks

void prog_check(struct ir_function *fun);

void check_insn_operand(struct ir_insn *insn);

void check_insn_users_use_insn(struct ir_insn *insn);

void check_users(struct ir_function *fun);

#endif
