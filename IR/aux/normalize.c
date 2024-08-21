// Normalization

#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_fun.h"
#include "ir_insn.h"

void normalize(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_value *v0       = &insn->values[0];
            struct ir_value *v1       = &insn->values[1];
            enum val_type    t0       = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
            enum val_type    t1       = insn->value_num >= 2 ? vtype(*v1) : UNDEF;
            enum val_type    tdst     = vtype_insn(insn);
            struct ir_insn  *dst_insn = dst(insn);
            if (insn->op == IR_INSN_ALLOC) {
                // Skip
            } else if (insn->op == IR_INSN_STORE) {
                // Should be converted to ASSIGN
                CRITICAL("Error");
            } else if (insn->op == IR_INSN_LOAD) {
                CRITICAL("Error");
            } else if (insn->op == IR_INSN_LOADRAW) {
                // OK
            } else if (insn->op == IR_INSN_STORERAW) {
                // OK
            } else if (insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL) {
                // Binary ALU
                if (t0 == STACK && t1 == CONST) {
                    // reg1 = add stack const
                    // ==>
                    // reg1 = stack
                    // reg1 = add reg1 const
                    struct ir_insn *new_insn = create_assign_insn_cg(insn, *v0, INSERT_FRONT);
                    insn_cg(new_insn)->dst   = dst_insn;
                    v0->type                 = IR_VALUE_INSN;
                    v0->data.insn_d          = dst_insn;
                } else if (t0 == REG && t1 == REG) {
                    // reg1 = add reg2 reg3
                    __u8 reg1 = insn_cg(dst_insn)->alloc_reg;
                    __u8 reg2 = insn_cg(v0->data.insn_d)->alloc_reg;
                    __u8 reg3 = insn_cg(v1->data.insn_d)->alloc_reg;
                    if (reg1 != reg2) {
                        if (reg1 == reg3) {
                            // Exchange reg2 and reg3
                            struct ir_value tmp = *v0;
                            *v0                 = *v1;
                            *v1                 = tmp;
                        } else {
                            // reg1 = add reg2 reg3
                            // ==>
                            // reg1 = reg2
                            // reg1 = add reg1 reg3
                            struct ir_insn *new_insn =
                                create_assign_insn_cg(insn, *v0, INSERT_FRONT);
                            DBGASSERT(dst_insn == fun->cg_info.regs[reg1]);
                            insn_cg(new_insn)->dst = dst_insn;
                            v0->type               = IR_VALUE_INSN;
                            v0->data.insn_d        = dst_insn;
                        }
                    }
                } else if (t0 == REG && t1 == CONST) {
                    // reg1 = add reg2 const
                    // ==>
                    // reg1 = reg2
                    // reg1 = add reg1 const
                    struct ir_insn *new_insn = create_assign_insn_cg(insn, *v0, INSERT_FRONT);
                    insn_cg(new_insn)->dst   = dst_insn;
                    v0->type                 = IR_VALUE_INSN;
                    v0->data.insn_d          = dst_insn;
                } else {
                    CRITICAL("Error");
                }
            } else if (insn->op == IR_INSN_ASSIGN) {
                // stack = reg
                // stack = const
                // reg = const
                // reg = stack
                // reg = reg
                if (tdst == STACK) {
                    DBGASSERT(t0 != STACK);
                    // Change to STORERAW
                    insn->op              = IR_INSN_STORERAW;
                    insn->addr_val.value  = ir_value_stack_ptr();
                    insn->addr_val.offset = -insn_cg(dst_insn)->spilled * 8;
                    insn->vr_type         = IR_VR_TYPE_64;
                } else {
                    if (t0 == STACK) {
                        // Change to LOADRAW
                        insn->op              = IR_INSN_LOADRAW;
                        insn->addr_val.value  = ir_value_stack_ptr();
                        insn->addr_val.offset = -insn_cg(v0->data.insn_d)->spilled * 8;
                        insn->vr_type         = IR_VR_TYPE_64;
                    }
                }
            } else if (insn->op == IR_INSN_RET) {
                // OK
            } else if (insn->op == IR_INSN_CALL) {
                // OK
            } else if (insn->op == IR_INSN_JA) {
                // OK
            } else if (insn->op >= IR_INSN_JEQ && insn->op < IR_INSN_PHI) {
                // jeq reg const/reg
                DBGASSERT(t0 == REG && (t1 == REG || t1 == CONST));
                // OK
            } else {
                CRITICAL("No such instruction");
            }
        }
    }
}
