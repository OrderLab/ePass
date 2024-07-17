#include "add_stack_offset.h"
#include "array.h"
#include "bpf_ir.h"
#include "ir_insn.h"

void add_stack_offset(struct ir_function *fun, __s16 offset) {
    struct array     users = fun->sp_users;
    struct ir_insn **pos;
    array_for(pos, users) {
        struct ir_insn *insn = *pos;

        if (insn->op == IR_INSN_LOADRAW || insn->op == IR_INSN_STORERAW) {
            insn->addr_val.offset += offset;
        }

        for (__u8 j = 0; j < insn->value_num; ++j) {
            if (insn->values[j].type == IR_VALUE_STACK_PTR) {
                // Stack pointer as value
                struct ir_value val;
                val.type                       = IR_VALUE_CONSTANT;
                val.data.constant_d.type       = IR_CONSTANT_S16;
                val.data.constant_d.data.s16_d = offset;
                struct ir_insn *new_insn =
                    create_add_insn(insn, insn->values[j], val, INSERT_FRONT);
                val.type        = IR_VALUE_INSN;
                val.data.insn_d = new_insn;
                insn->values[j] = val;
            }
        }
        if (insn->op == IR_INSN_PHI) {
            struct phi_value *pv_pos2;
            array_for(pv_pos2, insn->phi) {
                if (pv_pos2->value.type == IR_VALUE_STACK_PTR) {
                    // Stack pointer as value
                    struct ir_value val;
                    val.type                       = IR_VALUE_CONSTANT;
                    val.data.constant_d.type       = IR_CONSTANT_S16;
                    val.data.constant_d.data.s16_d = offset;
                    struct ir_insn *new_insn =
                        create_add_insn(insn, pv_pos2->value, val, INSERT_FRONT);
                    val.type        = IR_VALUE_INSN;
                    val.data.insn_d = new_insn;
                    pv_pos2->value = val;
                }
            }
        }
    }
    array_free(&fun->sp_users);
}
