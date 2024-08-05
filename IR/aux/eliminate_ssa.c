#include "eliminate_ssa.h"
#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "ir_insn.h"

// Eliminate SSA Phi nodes
// Using "Method I" in paper "Translating Out of Static Single Assignment Form"
void elim_ssa(struct ir_function *fun) {
    struct array phi_insns = INIT_ARRAY(struct ir_insn *);

    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            if (insn->op == IR_INSN_PHI) {
                array_push(&phi_insns, &insn);
            } else {
                break;
            }
        }
    }

    struct ir_insn **pos2;
    array_for(pos2, phi_insns) {
        struct ir_insn *insn = *pos2;
        struct phi_value *pos3;
        array_for(pos3, insn->phi) {
            create_assign_insn_bb(pos3->bb, pos3->value, INSERT_BACK_BEFORE_JMP);
        }
    }

    array_free(&phi_insns);
}