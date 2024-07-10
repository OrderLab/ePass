#include "ir_insn.h"
#include <stdio.h>
#include "array.h"
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

void erase_insn(struct ir_insn *insn) {
    list_del(&insn->list_ptr);
    __free(insn);
}

void insert_at(struct ir_insn *new_insn, struct ir_insn *insn, enum insert_position pos) {
    if (pos == INSERT_BACK) {
        list_add(&new_insn->list_ptr, &insn->list_ptr);
    } else {
        list_add_tail(&new_insn->list_ptr, &insn->list_ptr);
    }
}

void insert_at_bb(struct ir_insn *new_insn, struct ir_basic_block *bb, enum insert_position pos) {
    if (pos == INSERT_BACK) {
        list_add_tail(&new_insn->list_ptr, &bb->ir_insn_head);
    } else {
        list_add(&new_insn->list_ptr, &bb->ir_insn_head);
    }
}

struct ir_insn *create_alloc_insn_base(struct ir_basic_block *bb, enum ir_vr_type type) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_ALLOC;
    new_insn->vr_type        = type;
    return new_insn;
}

struct ir_insn *create_alloc_insn(struct ir_insn *insn, enum ir_vr_type type,
                                  enum insert_position pos) {
    struct ir_insn *new_insn = create_alloc_insn_base(insn->parent_bb, type);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_alloc_insn_bb(struct ir_basic_block *bb, enum ir_vr_type type,
                                     enum insert_position pos) {
    struct ir_insn *new_insn = create_alloc_insn_base(bb, type);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

void val_add_user(struct ir_value val, struct ir_insn *user) {
    if (val.type != IR_VALUE_INSN) {
        return;
    }
    array_push_unique(&val.data.insn_d->users, &user);
}

struct ir_insn *create_store_insn_base(struct ir_basic_block *bb, struct ir_insn *insn,
                                       struct ir_value val) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_STORE;
    struct ir_value nv;
    nv.type             = IR_VALUE_INSN;
    nv.data.insn_d      = insn;
    new_insn->values[0] = nv;
    new_insn->values[1] = val;
    val_add_user(nv, new_insn);
    return new_insn;
}

struct ir_insn *create_store_insn(struct ir_insn *insn, struct ir_insn *st_insn,
                                  struct ir_value val, enum insert_position pos) {
    struct ir_insn *new_insn = create_store_insn_base(insn->parent_bb, st_insn, val);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_store_insn_bb(struct ir_basic_block *bb, struct ir_insn *st_insn,
                                     struct ir_value val, enum insert_position pos) {
    struct ir_insn *new_insn = create_store_insn_base(bb, st_insn, val);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

struct ir_insn *create_load_insn_base(struct ir_basic_block *bb, enum ir_vr_type ty,
                                      struct ir_value val) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_LOAD;
    new_insn->vr_type        = ty;
    new_insn->values[0]      = val;
    val_add_user(val, new_insn);
    return new_insn;
}

struct ir_insn *create_load_insn(struct ir_insn *insn, enum ir_vr_type ty, struct ir_value val,
                                 enum insert_position pos) {
    struct ir_insn *new_insn = create_load_insn_base(insn->parent_bb, ty, val);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_load_insn_bb(struct ir_basic_block *bb, enum ir_vr_type ty,
                                    struct ir_value val, enum insert_position pos) {
    struct ir_insn *new_insn = create_load_insn_base(bb, ty, val);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

struct ir_insn *create_add_insn_base(struct ir_basic_block *bb, struct ir_value val1,
                                     struct ir_value val2) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_ADD;
    new_insn->values[0]      = val1;
    new_insn->values[1]      = val2;
    val_add_user(val1, new_insn);
    val_add_user(val2, new_insn);
    return new_insn;
}

struct ir_insn *create_add_insn(struct ir_insn *insn, struct ir_value val1, struct ir_value val2,
                                enum insert_position pos) {
    struct ir_insn *new_insn = create_add_insn_base(insn->parent_bb, val1, val2);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_add_insn_bb(struct ir_basic_block *bb, struct ir_value val1,
                                   struct ir_value val2, enum insert_position pos) {
    struct ir_insn *new_insn = create_add_insn_base(bb, val1, val2);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

struct ir_insn *prev_insn(struct ir_insn *insn) {
    struct list_head *prev = insn->list_ptr.prev;
    if (list_empty(prev)) {
        return NULL;
    }
    return list_entry(prev, struct ir_insn, list_ptr);
}

struct ir_insn *create_jlt_insn_base(struct ir_basic_block *bb, struct ir_value val1,
                                     struct ir_value val2, struct ir_basic_block *to_bb1,
                                     struct ir_basic_block *to_bb2) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_JLT;
    new_insn->values[0]      = val1;
    new_insn->values[1]      = val2;
    new_insn->bb1            = to_bb1;
    new_insn->bb2            = to_bb2;
    val_add_user(val1, new_insn);
    val_add_user(val2, new_insn);
    return new_insn;
}

struct ir_insn *create_jlt_insn(struct ir_insn *insn, struct ir_value val1, struct ir_value val2,
                                struct ir_basic_block *to_bb1, struct ir_basic_block *to_bb2,
                                enum insert_position pos) {
    struct ir_insn *new_insn = create_jlt_insn_base(insn->parent_bb, val1, val2, to_bb1, to_bb2);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_jlt_insn_bb(struct ir_basic_block *bb, struct ir_value val1,
                                   struct ir_value val2, struct ir_basic_block *to_bb1,
                                   struct ir_basic_block *to_bb2, enum insert_position pos) {
    struct ir_insn *new_insn = create_jlt_insn_base(bb, val1, val2, to_bb1, to_bb2);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}
