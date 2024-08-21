// Normalization

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
            struct ir_value         *v0       = &insn->values[0];
            struct ir_value         *v1       = &insn->values[1];
            enum val_type            t0       = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
            enum val_type            t1       = insn->value_num >= 2 ? vtype(*v1) : UNDEF;
            enum val_type            tdst     = vtype_insn(insn);
            struct ir_insn_cg_extra *extra    = insn_cg(insn);
            struct ir_insn          *dst_insn = dst(insn);
            if (insn->op == IR_INSN_ALLOC) {
                // Skip
            } else if (insn->op == IR_INSN_STORE) {
                // Should be converted to ASSIGN
                CRITICAL("Error");
            } else if (insn->op == IR_INSN_LOAD) {
                // OK
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
                } else {
                    CRITICAL("Error");
                }
            } else if (insn->op == IR_INSN_ASSIGN) {
                // stack = reg
                // stack = const
                // reg = const
                // reg = stack
                // reg = reg
                if (tdst == STACK && t0 == STACK) {
                    load_stack_to_r0(fun, insn, v0);
                    res = 1;
                }
                // TODO: constant to stack: might need to first load to reg
            } else if (insn->op == IR_INSN_RET) {
                // ret const/reg
                // Done in explicit_reg pass
                DBGASSERT(insn->value_num == 0);
            } else if (insn->op == IR_INSN_CALL) {
                // call()
                // Should have no arguments
                DBGASSERT(insn->value_num == 0);
            } else if (insn->op == IR_INSN_JA) {
                // OK
            } else if (insn->op >= IR_INSN_JEQ && insn->op < IR_INSN_PHI) {
                // jeq reg const/reg
                if ((t0 != REG && t1 == REG) || (t0 == CONST && t1 == STACK)) {
                    struct ir_value tmp = *v0;
                    *v0                 = *v1;
                    *v1                 = tmp;
                    enum val_type ttmp  = t0;
                    t0                  = t1;
                    t1                  = ttmp;
                    // No need to spill here
                }

                if (t0 == REG) {
                    // jeq reg reg ==> OK
                    // jeq reg const ==> OK
                    // jeq reg stack
                    // ==>
                    // reg2 = stack
                    // jeq reg reg2
                    if (t1 == STACK) {
                        __u8            reg1     = insn_cg(v0->data.insn_d)->alloc_reg;
                        __u8            reg2     = reg1 == 0 ? 1 : 0;
                        struct ir_insn *new_insn = create_assign_insn_cg(insn, *v1, INSERT_FRONT);
                        insn_cg(new_insn)->dst   = fun->cg_info.regs[reg2];
                        v1->type                 = IR_VALUE_INSN;
                        v1->data.insn_d          = fun->cg_info.regs[reg2];
                        res                      = 1;
                    }
                } else {
                    // jeq const1 const2
                    // ==>
                    // %tmp = const1
                    // jeq %tmp const2
                    if (t0 == CONST && t1 == CONST) {
                        struct ir_insn *new_insn = create_assign_insn_cg(insn, *v0, INSERT_FRONT);
                        v0->type                 = IR_VALUE_INSN;
                        v0->data.insn_d          = new_insn;
                        res                      = 1;
                    }
                    // jeq stack const
                    if (t0 == STACK && t1 == CONST) {
                        load_stack_to_r0(fun, insn, v0);
                        res = 1;
                    }
                    // jeq stack stack
                    if (t0 == STACK && t1 == STACK) {
                        load_stack_to_r0(fun, insn, v0);
                        res = 1;
                    }
                }
            } else {
                CRITICAL("No such instruction");
            }
        }
    }
}
