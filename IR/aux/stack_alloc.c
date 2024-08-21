// Allocate stack in code generation

#include <stdio.h>
#include "code_gen.h"
#include "ir_fun.h"

void calc_callee_num(struct ir_function *fun) {
    __u8 reg_used[MAX_BPF_REG] = {0};

    struct ir_insn **pos;
    array_for(pos, fun->cg_info.all_var) {
        struct ir_insn_cg_extra *extra = insn_cg(*pos);
        reg_used[extra->alloc_reg]     = 1;
    }
    size_t off = 0;
    for (__u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
        if (reg_used[i]) {
            off++;
        }
    }
    fun->cg_info.callee_num = off;
}

void calc_stack_size(struct ir_function *fun) {
    // Check callee
    size_t off = 0;
    off += fun->cg_info.callee_num * 8;
    // Check all VR
    size_t           max = 0;
    struct ir_insn **pos;
    array_for(pos, fun->cg_info.all_var) {
        struct ir_insn_cg_extra *extra = insn_cg(*pos);
        if (extra->spilled > 0) {
            // Spilled!
            if (extra->spilled > max) {
                max = extra->spilled;
            }
        }
    }
    fun->cg_info.stack_offset = -(off + max * 8);
    printf("Stack size: %d\n", fun->cg_info.stack_offset);
}
