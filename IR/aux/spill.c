#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_insn.h"

enum val_type vtype(struct ir_value val) {
    if (val.type == IR_VALUE_INSN) {
        struct ir_insn          *insn  = dst(val.data.insn_d);
        struct ir_insn_cg_extra *extra = insn_cg(insn);
        if (extra->spilled) {
            return STACK;
        } else {
            return REG;
        }
    } else if (val.type == IR_VALUE_CONSTANT) {
        return CONST;
    } else if (val.type == IR_VALUE_STACK_PTR) {
        return STACK;
    } else {
        CRITICAL("No such value type for dst");
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
            struct ir_value v0 = insn->values[0];
            struct ir_value v1 = insn->values[1];
            if (insn->op == IR_INSN_ALLOC) {
                // dst = alloc <size>
                // Nothing to do
            } else if (insn->op == IR_INSN_STORE) {
                // store v0(dst) v1
                // v0: reg ==> v1: reg, const, stack
                // v0: stack ==> v1: reg, const
                if (vtype(v0) == STACK && vtype(v1) == STACK) {
                    // Cannot directly copy stack value to stack
                    // Example:
                    // store s-8 s-16
                    // -->
                    // %tmp = load s-16
                    // store s-8 %tmp
                    struct ir_insn *tmp = create_insn_base_cg(bb);
                    insert_at(tmp, insn, INSERT_FRONT);
                    tmp->op = IR_INSN_LOAD;
                    tmp->value_num = 1;
                    tmp->values[0] = 0;
                    // No need to add users at this point
                }
            } else if (insn->op == IR_INSN_LOAD) {
            } else if (insn->op == IR_INSN_LOADRAW) {
            } else if (insn->op == IR_INSN_STORE) {
            } else if (insn->op == IR_INSN_STORERAW) {
            } else if (insn->op == IR_INSN_ASSIGN) {
                // dst = <val>
                // MOV dst val

            } else if (insn->op == IR_INSN_CALL) {
                // call()
                // Should have no arguments
                DBGASSERT(insn->value_num == 0);
            } else {
                CRITICAL("No such instruction");
            }
        }
    }
    return res;
}
