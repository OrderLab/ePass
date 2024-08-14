#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
enum val_type {
    REG,
    CONST,
    STACK
};

enum val_type vtype(struct ir_value val) {
    if (val.type == IR_VALUE_INSN) {
        struct ir_insn          *insn  = dst(val.data.insn_d);
        struct ir_insn_cg_extra *extra = insn_cg(insn);
        if (extra->spilled) {
            return STACK;
        } else {
            return REG;
        }
    } else {
    }
}

int check_need_spill(struct ir_function *fun) {
    // Check if all instruction values are OK for translating
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            if (insn->op == IR_INSN_ALLOC) {
                // dst = alloc <size>
                // Nothing to do
            } else if (insn->op == IR_INSN_STORE) {
                // store v0 v1
                // v0: reg + v1: reg, const, stack
                // v0: stack + v1: reg, const

            } else if (insn->op == IR_INSN_ASSIGN) {
                // dst = <val>
                // MOV dst val

            } else {
                CRITICAL("No such instruction");
            }
        }
    }
    return 0;
}

void spill(struct ir_function *fun) {}