#include "add_stack_offset.h"
#include <stdio.h>
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
            continue;
        }
        struct array      value_uses = find_value_uses(insn);
        struct ir_value **pos2;
        array_for(pos2, value_uses) {
            struct ir_value *val = *pos2;
            if (val->type == IR_VALUE_STACK_PTR) {
                // Stack pointer as value
                struct ir_value new_val;
                new_val.type                       = IR_VALUE_CONSTANT;
                new_val.data.constant_d.type       = IR_CONSTANT_S16;
                new_val.data.constant_d.data.s16_d = offset;
                struct ir_insn *new_insn =
                    create_bin_insn(insn, *val, new_val, IR_INSN_ADD, INSERT_FRONT);
                new_val.type        = IR_VALUE_INSN;
                new_val.data.insn_d = new_insn;
                *val                = new_val;
            }
        }
        array_free(&value_uses);
    }
    array_free(&fun->sp_users);
}
