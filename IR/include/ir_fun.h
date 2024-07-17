#ifndef __BPF_IR_FUN_H__
#define __BPF_IR_FUN_H__

#include "bpf_ir.h"

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
};

// Helper functions

void clean_env(struct ir_function *);

void clean_id(struct ir_function *);

void print_ir_prog(struct ir_function *);

#endif
