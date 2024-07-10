#include "phi_pass.h"
#include "bpf_ir.h"

void remove_trivial_phi(struct ir_function *fun) {}

void try_remove_trivial_phi(struct ir_insn *phi) {
    if (phi->op != IR_INSN_PHI) {
        return;
    }
    struct ir_value *same = NULL;
    for (size_t i = 0; i < phi->phi.num_elem; ++i) {
        struct phi_value pv = ((struct phi_value *)(phi->phi.data))[i];
        if (pv.value.type == IR_VALUE_INSN && same->type == IR_VALUE_INSN &&
            (pv.value.data.insn_d == same->data.insn_d || pv.value.data.insn_d == phi)) {
            continue;
        }
        if (same) {
            return;
        }
        same = &pv.value;
    }
    struct ir_value replica;
    if (!same) {
        replica.type = IR_VALUE_UNDEF;
    } else {
        replica = *same;
    }
    for (size_t i = 0; i < phi->users.num_elem; ++i) {
        struct ir_insn *user = ((struct ir_insn **)(phi->users.data))[i];
    }
}
