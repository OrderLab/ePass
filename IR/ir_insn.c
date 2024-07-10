#include "ir_insn.h"
#include "bpf_ir.h"
#include "list.h"

struct ir_insn *create_insn_base(struct ir_insn *insn) {
    struct ir_insn *new_insn = __malloc(sizeof(struct ir_insn));
    new_insn->parent_bb      = insn->parent_bb;
    return new_insn;
}

void insert_at(struct ir_insn *new_insn, struct ir_insn *insn, enum insert_position pos) {
    if (pos == INSERT_BACK) {
        list_add(&new_insn->ptr, &insn->ptr);
    } else {
        list_add_tail(&new_insn->ptr, &insn->ptr);
    }
}

void create_alloc_insn(struct ir_insn *insn, enum insert_position pos) {
    struct ir_insn *new_insn = create_insn_base(insn);
    new_insn->op             = IR_INSN_ALLOC;
    insert_at(new_insn, insn, pos);
}
