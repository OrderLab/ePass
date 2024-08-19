#include <linux/bpf.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_insn.h"

enum val_type vtype_insn(struct ir_insn *insn) {
    insn                           = dst(insn);
    struct ir_insn_cg_extra *extra = insn_cg(insn);
    if (extra->spilled) {
        return STACK;
    } else {
        return REG;
    }
}

enum val_type vtype(struct ir_value val) {
    if (val.type == IR_VALUE_INSN) {
        return vtype_insn(val.data.insn_d);
    } else if (val.type == IR_VALUE_CONSTANT) {
        return CONST;
    } else if (val.type == IR_VALUE_STACK_PTR) {
        return STACK;
    } else {
        CRITICAL("No such value type for dst");
    }
}

void load_stack_to_vr(struct ir_insn *insn, struct ir_value *val, enum ir_vr_type ty) {
    struct ir_insn *tmp = create_insn_base_cg(insn->parent_bb);
    insert_at(tmp, insn, INSERT_FRONT);
    tmp->op        = IR_INSN_LOAD;
    tmp->value_num = 1;
    tmp->values[0] = *val;
    tmp->vr_type   = ty;

    val->type        = IR_VALUE_INSN;
    val->data.insn_d = tmp;
}

void add_stack_offset_vr(struct ir_function *fun, size_t num) {
    struct ir_insn **pos;
    array_for(pos, fun->cg_info.all_var) {
        struct ir_insn_cg_extra *extra = insn_cg(*pos);
        if (extra->spilled > 0) {
            extra->spilled += num;
        }
    }
}

void spill_callee(struct ir_function *fun) {
    // Spill Callee save registers if used
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
    add_stack_offset_vr(fun, off);
    off = 0;
    for (__u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
        // All callee saved registers
        if (reg_used[i]) {
            off++;
            // Spill at sp-off
            struct ir_insn *st = create_assign_insn_bb_cg(fun->entry, ir_value_insn(fun->cg_info.regs[i]), INSERT_FRONT);
            struct ir_insn_cg_extra *extra = insn_cg(st);
            extra->allocated = 1;
            extra->spilled = off;
        }
    }
}

int check_need_spill(struct ir_function *fun) {
    // Check if all instruction values are OK for translating
    int                     res = 0;
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_value *v0 = &insn->values[0];
            struct ir_value *v1 = &insn->values[1];
            if (insn->op == IR_INSN_ALLOC) {
                // dst = alloc <size>
                // Nothing to do
            } else if (insn->op == IR_INSN_STORE) {
                // store v0(dst) v1
                // v0: reg ==> v1: reg, const, stack
                // v0: stack ==> v1: reg, const
                if (vtype(*v0) == STACK && vtype(*v1) == STACK) {
                    // Cannot directly copy stack value to stack
                    // Example:
                    // store s-8 s-16
                    // -->
                    // %tmp = load s-16
                    // store s-8 %tmp

                    // First get type of the dst
                    enum ir_vr_type ty = v0->data.insn_d->vr_type;

                    load_stack_to_vr(insn, v1, ty);
                    res = 1;
                }
            } else if (insn->op == IR_INSN_LOAD) {
                // OK
            } else if (insn->op == IR_INSN_LOADRAW) {
                // OK
            } else if (insn->op == IR_INSN_STORERAW) {
                // Built-in store instruction, OK
            } else if (insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL) {
                // Binary ALU
                // add reg reg
                // add const reg
                // There should be no stack
                if (vtype(*v0) == STACK) {
                    load_stack_to_vr(insn, v0, IR_VR_TYPE_U64);
                    res = 1;
                }
                if (vtype(*v1) == STACK) {
                    load_stack_to_vr(insn, v1, IR_VR_TYPE_U64);
                    res = 1;
                }
            } else if (insn->op == IR_INSN_ASSIGN) {
                // dst = <val>
                // MOV dst val
                if (vtype_insn(insn) == STACK && vtype(*v0) == STACK) {
                    load_stack_to_vr(insn, v0, IR_VR_TYPE_U64);
                    res = 1;
                }
            } else if (insn->op == IR_INSN_RET) {
                // ret const/reg
                // Done in explicit_reg pass
                DBGASSERT(insn->value_num == 0);
            } else if (insn->op == IR_INSN_CALL) {
                // call()
                // Should have no arguments
                DBGASSERT(insn->value_num == 0);
            } else if (insn->op == IR_INSN_JA) {
                // TODO
            } else if (insn->op >= IR_INSN_JEQ && insn->op < IR_INSN_PHI) {
                // TODO
            } else {
                CRITICAL("No such instruction");
            }
        }
    }
    return res;
}
