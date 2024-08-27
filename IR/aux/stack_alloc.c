// Allocate stack in code generation

#include <stdio.h>
#include "code_gen.h"
#include "dbg.h"
#include "ir_fun.h"
#include "array.h"
#include "bpf_ir.h"
#include "ir_insn.h"

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
    if (fun->cg_info.spill_callee) {
        off += fun->cg_info.callee_num * 8;
    }
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

void add_stack_offset_pre_cg(struct ir_function *fun) {
    // Pre CG
    struct array     users = fun->sp_users;
    struct ir_insn **pos;
    array_for(pos, users) {
        struct ir_insn *insn = *pos;

        if (insn->op == IR_INSN_LOADRAW || insn->op == IR_INSN_STORERAW) {
            // Also need to check if the value points to an INSN or a STACKPTR
            // insn->addr_val.offset += offset;
            continue;
        }
        struct array      value_uses = get_operands(insn);
        struct ir_value **pos2;
        array_for(pos2, value_uses) {
            struct ir_value *val = *pos2;
            if (val->type == IR_VALUE_STACK_PTR) {
                // Stack pointer as value
                struct ir_value new_val;
                new_val.type = IR_VALUE_CONSTANT_RAWOFF;
                struct ir_insn *new_insn =
                    create_bin_insn(insn, *val, new_val, IR_INSN_ADD, INSERT_FRONT);
                new_val.type        = IR_VALUE_INSN;
                new_val.data.insn_d = new_insn;
                *val                = new_val;
            }
        }
        array_free(&value_uses);
    }
}

void add_stack_offset(struct ir_function *fun, __s16 offset) {
    struct array     users = fun->sp_users;
    struct ir_insn **pos;
    array_for(pos, users) {
        struct ir_insn *insn = *pos;

        if (insn->op == IR_INSN_LOADRAW || insn->op == IR_INSN_STORERAW) {
            if (insn->addr_val.value.type == IR_VALUE_STACK_PTR) {
                insn->addr_val.offset += offset;
                continue;
            }
        }
        struct array      value_uses = get_operands(insn);
        struct ir_value **pos2;
        array_for(pos2, value_uses) {
            struct ir_value *val = *pos2;
            DBGASSERT(val->type != IR_VALUE_STACK_PTR);
            if (val->type == IR_VALUE_CONSTANT_RAWOFF) {
                // Stack pointer as value
                val->data.constant_d = offset;
            }
        }
        array_free(&value_uses);
    }
}
