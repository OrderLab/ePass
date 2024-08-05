#include "code_gen.h"
#include "array.h"
#include "bpf_ir.h"
#include "dbg.h"
#include "ir_fun.h"
#include "ir_insn.h"

// Convert from TSSA to CSSA
// Using "Method I" in paper "Translating Out of Static Single Assignment Form"
void to_cssa(struct ir_function *fun) {
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
        // Create the moved PHI insn
        struct ir_insn   *new_phi = create_phi_insn(insn, INSERT_FRONT);
        struct phi_value *pos3;
        array_for(pos3, insn->phi) {
            struct ir_insn *new_insn =
                create_assign_insn_bb(pos3->bb, pos3->value, INSERT_BACK_BEFORE_JMP);
            // Remove use
            val_remove_user(pos3->value, insn);
            phi_add_operand(new_phi, pos3->bb, ir_value_insn(new_insn));
        }

        array_free(&insn->phi);
        insn->op            = IR_INSN_ASSIGN;
        struct ir_value val = ir_value_insn(new_phi);
        insn->values[0]     = val;
        insn->value_num     = 1;
        val_add_user(val, insn);
    }

    array_free(&phi_insns);
}

// Remove PHI insn
void remove_phi(struct ir_function *fun) {
    // dst information ready
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
        struct ir_insn   *insn = *pos2;
        struct ir_insn   *repr = NULL;
        struct phi_value *pos3;
        array_for(pos3, insn->phi) {
            if (!repr) {
                repr = pos3->value.data.insn_d;
            } else {
                insn_cg(pos3->value.data.insn_d)->dst = repr;
            }
        }
        if (!repr) {
            CRITICAL("Empty Phi not removed!");
        }

        replace_all_usage(insn, ir_value_insn(repr));
        erase_insn(insn);
    }

    array_free(&phi_insns);
}
