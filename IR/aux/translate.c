#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"

void translate(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *extra = insn_cg(insn);
            if (insn->op == IR_INSN_ALLOC) {
                // dst = alloc <size>
                // Nothing to do
            } else if (insn->op == IR_INSN_STORE) {
            } else if (insn->op == IR_INSN_LOAD) {
                // OK
            } else if (insn->op == IR_INSN_LOADRAW) {
                // OK
            } else if (insn->op == IR_INSN_STORERAW) {
            } else if (insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL) {
            } else if (insn->op == IR_INSN_ASSIGN) {
                // dst = <val>
                // MOV dst val

            } else if (insn->op == IR_INSN_RET) {
            } else if (insn->op == IR_INSN_CALL) {
            } else if (insn->op == IR_INSN_JA) {
            } else if (insn->op >= IR_INSN_JEQ && insn->op < IR_INSN_PHI) {
            } else {
                CRITICAL("No such instruction");
            }
        }
    }
}
