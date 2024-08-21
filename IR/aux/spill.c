#include <linux/bpf.h>
#include <stdio.h>
#include <time.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_insn.h"
#include "ir_helper.h"

enum val_type vtype_insn(struct ir_insn *insn) {
    insn = dst(insn);
    if (insn == NULL) {
        // Void
        return UNDEF;
    }
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
        return REG;
    } else {
        CRITICAL("No such value type for dst");
    }
}

void load_stack_to_r0(struct ir_function *fun, struct ir_insn *insn, struct ir_value *val) {
    struct ir_insn *tmp = create_assign_insn_cg(insn, *val, INSERT_FRONT);
    insn_cg(tmp)->dst   = fun->cg_info.regs[0];

    val->type        = IR_VALUE_INSN;
    val->data.insn_d = fun->cg_info.regs[0];
}

void load_const_to_vr(struct ir_insn *insn, struct ir_value *val) {
    struct ir_insn *tmp = create_assign_insn_cg(insn, *val, INSERT_FRONT);

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
    // Spill Callee saved registers if used
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
    DBGASSERT(off == fun->cg_info.callee_num);
    add_stack_offset_vr(fun, off);
    off = 0;
    for (__u8 i = BPF_REG_6; i < BPF_REG_10; ++i) {
        // All callee saved registers
        if (reg_used[i]) {
            off++;
            // Spill at sp-off
            // struct ir_insn *st = create_assign_insn_bb_cg(
            //     fun->entry, ir_value_insn(fun->cg_info.regs[i]), INSERT_FRONT);
            struct ir_insn *st = create_insn_base_cg(fun->entry);
            insert_at_bb(st, fun->entry, INSERT_FRONT);
            st->op        = IR_INSN_STORERAW;
            st->values[0] = ir_value_insn(fun->cg_info.regs[i]);
            st->value_num = 1;
            st->vr_type   = IR_VR_TYPE_U64;
            struct ir_value val;
            val.type                       = IR_VALUE_STACK_PTR;
            st->addr_val.value             = val;
            st->addr_val.offset            = -off * 8;
            struct ir_insn_cg_extra *extra = insn_cg(st);
            extra->dst                     = NULL;

            struct ir_basic_block **pos2;
            array_for(pos2, fun->end_bbs) {
                struct ir_basic_block *bb = *pos2;
                struct ir_insn        *ld = create_insn_base_cg(bb);
                insert_at_bb(ld, bb, INSERT_BACK_BEFORE_JMP);
                ld->op        = IR_INSN_LOADRAW;
                ld->value_num = 0;
                ld->vr_type   = IR_VR_TYPE_U64;
                struct ir_value val;
                val.type            = IR_VALUE_STACK_PTR;
                ld->addr_val.value  = val;
                ld->addr_val.offset = -off * 8;

                extra      = insn_cg(ld);
                extra->dst = fun->cg_info.regs[i];
            }
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
            struct ir_value         *v0       = &insn->values[0];
            struct ir_value         *v1       = &insn->values[1];
            enum val_type            t0       = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
            enum val_type            t1       = insn->value_num >= 2 ? vtype(*v1) : UNDEF;
            enum val_type            tdst     = vtype_insn(insn);
            struct ir_insn_cg_extra *extra    = insn_cg(insn);
            struct ir_insn          *dst_insn = dst(insn);
            if (insn->op == IR_INSN_ALLOC) {
                // dst = alloc <size>
                // Nothing to do
            } else if (insn->op == IR_INSN_STORE) {
                // store v0(dst) v1
                // Eequivalent to `v0 = v1`
                // TODO: sized store
                // Currently all load & store are 8 bytes
                insn->op = IR_INSN_ASSIGN;
                DBGASSERT(v0->type == IR_VALUE_INSN);  // Should be guaranteed by prog_check
                extra->dst      = v0->data.insn_d;
                insn->value_num = 1;
                *v0             = *v1;
                res             = 1;
            } else if (insn->op == IR_INSN_LOAD) {
                // OK
            } else if (insn->op == IR_INSN_LOADRAW) {
                // OK
            } else if (insn->op == IR_INSN_STORERAW) {
                // Built-in store instruction, OK
            } else if (insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL) {
                // Binary ALU
                // reg = add reg reg
                // reg = add reg const
                // There should be NO stack
                if (tdst == STACK) {
                    // stack = add ? ?
                    // ==>
                    // R0 = add ? ?
                    // stack = R0
                    extra->dst          = fun->cg_info.regs[0];
                    struct ir_insn *tmp = create_assign_insn_cg(
                        insn, ir_value_insn(fun->cg_info.regs[0]), INSERT_BACK);
                    insn_cg(tmp)->dst = dst_insn;
                    res               = 1;
                } else {
                    if ((t0 != REG && t1 == REG) || (t0 == CONST && t1 == STACK)) {
                        // reg = add !reg reg
                        // ==>
                        // reg = add reg !reg
                        struct ir_value tmp = *v0;
                        *v0                 = *v1;
                        *v1                 = tmp;
                        enum val_type ttmp  = t0;
                        t0                  = t1;
                        t1                  = ttmp;
                        // No need to spill here
                    }
                    if (t0 == REG) {
                        // reg = add reg reg ==> OK
                        // reg = add reg const ==> OK

                        // reg1 = add reg2 stack
                        // ==>
                        // If reg1 != reg2,
                        //   reg1 = stack
                        //   reg1 = add reg2 reg1
                        // Else
                        //   Choose reg3 != reg1,
                        //   reg3 = stack
                        //   reg1 = add reg1 reg3
                        if (t1 == STACK) {
                            __u8 reg1 = insn_cg(dst_insn)->alloc_reg;
                            __u8 reg2 = insn_cg(v0->data.insn_d)->alloc_reg;
                            if (reg1 == reg2) {
                                __u8            reg = reg1 == 0 ? 1 : 0;
                                struct ir_insn *new_insn =
                                    create_assign_insn_cg(insn, *v1, INSERT_FRONT);
                                insn_cg(new_insn)->dst = fun->cg_info.regs[reg];
                                v1->type               = IR_VALUE_INSN;
                                v1->data.insn_d        = fun->cg_info.regs[reg];
                            } else {
                                struct ir_insn *new_insn =
                                    create_assign_insn_cg(insn, *v1, INSERT_FRONT);
                                insn_cg(new_insn)->dst = fun->cg_info.regs[reg1];
                                v1->type               = IR_VALUE_INSN;
                                v1->data.insn_d        = fun->cg_info.regs[reg1];
                            }
                            res = 1;
                        }
                    } else {
                        // reg = add const const ==> OK
                        // reg = add c1 c2
                        // ==>
                        // reg = c1
                        // reg = add reg c2
                        // OK

                        // reg = add stack stack
                        if (t0 == STACK && t1 == STACK) {
                            // reg1 = add stack1 stack2
                            // ==>
                            // Found reg2 != reg1
                            // reg1 = stack1
                            // reg1 = add reg1 stack2
                            __u8            reg1 = insn_cg(dst_insn)->alloc_reg;
                            struct ir_insn *new_insn =
                                create_assign_insn_cg(insn, *v0, INSERT_FRONT);
                            insn_cg(new_insn)->dst = fun->cg_info.regs[reg1];
                            v0->type               = IR_VALUE_INSN;
                            v0->data.insn_d        = fun->cg_info.regs[reg1];
                            res                    = 1;
                        }
                        // reg = add stack const ==> OK
                        // ==>
                        // reg = stack
                        // reg = add reg const
                    }
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
    return res;
}
