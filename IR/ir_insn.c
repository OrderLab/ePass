#include "ir_insn.h"
#include "bpf_ir.h"
#include "dbg.h"
#include "list.h"

struct ir_insn *create_insn_base(struct ir_basic_block *bb) {
    struct ir_insn *new_insn = __malloc(sizeof(struct ir_insn));
    new_insn->parent_bb      = bb;
    return new_insn;
}

__u8 is_last_insn(struct ir_insn *insn) {
    return insn->parent_bb->ir_insn_head.prev == &insn->list_ptr;
}

void insert_at(struct ir_insn *new_insn, struct ir_insn *insn, enum insert_position pos) {
    if (pos == INSERT_BACK) {
        if (is_last_insn(insn)) {
            CRITICAL("Cannot insert at the back of the last instruction");
        }
        list_add(&new_insn->list_ptr, &insn->list_ptr);
    } else {
        list_add_tail(&new_insn->list_ptr, &insn->list_ptr);
    }
}

struct ir_insn *create_alloc_insn_base(struct ir_basic_block *bb, enum ir_vr_type type) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_ALLOC;
    new_insn->vr_type        = type;
    return new_insn;
}

void create_alloc_insn(struct ir_insn *insn, enum ir_vr_type type, enum insert_position pos) {
    struct ir_insn *new_insn = create_alloc_insn_base(insn->parent_bb, type);
    insert_at(new_insn, insn, pos);
}
