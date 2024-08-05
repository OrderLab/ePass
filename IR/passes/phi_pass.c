#include "phi_pass.h"
#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "ir_insn.h"
#include "list.h"

void try_remove_trivial_phi(struct ir_insn *phi) {
    if (phi->op != IR_INSN_PHI) {
        return;
    }
    // print_raw_ir_insn(phi);
    struct ir_value   same;
    __u8              same_has_value = 0;
    struct phi_value *pv_pos;
    array_for(pv_pos, phi->phi) {
        struct phi_value pv = *pv_pos;
        if (pv.value.type == IR_VALUE_INSN && ((same_has_value && same.type == IR_VALUE_INSN &&
                                                pv.value.data.insn_d == same.data.insn_d) ||
                                               pv.value.data.insn_d == phi)) {
            continue;
        }
        if (same_has_value) {
            return;
        }
        same           = pv.value;
        same_has_value = 1;
    }
    // printf("Phi to remove: ");
    // print_raw_ir_insn(phi);
    if (!same_has_value) {
        same.type = IR_VALUE_UNDEF;
    }
    struct ir_value phi_val;
    phi_val.type        = IR_VALUE_INSN;
    phi_val.data.insn_d = phi;
    struct ir_insn **pos;
    array_for(pos, phi->users) {
        struct ir_insn *user = *pos;
        if (user == phi) {
            continue;
        }

        struct array      value_uses = get_operands(user);
        struct ir_value **pos2;
        array_for(pos2, value_uses) {
            if (ir_value_equal(**pos2, phi_val)) {
                **pos2 = same;
            }
        }
        array_free(&value_uses);
    }
    erase_insn(phi);
}

void remove_trivial_phi(struct ir_function *fun) {
    for (size_t i = 0; i < fun->reachable_bbs.num_elem; ++i) {
        struct ir_basic_block *bb = ((struct ir_basic_block **)(fun->reachable_bbs.data))[i];
        struct ir_insn        *pos, *n;
        list_for_each_entry_safe(pos, n, &bb->ir_insn_head, list_ptr) {
            try_remove_trivial_phi(pos);
        }
    }
}
