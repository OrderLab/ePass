#include "ir_insn.h"
#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "dbg.h"
#include "ir_bb.h"
#include "list.h"

struct ir_insn *create_insn_base(struct ir_basic_block *bb) {
    struct ir_insn *new_insn = __malloc(sizeof(struct ir_insn));
    new_insn->parent_bb      = bb;
    return new_insn;
}

struct array get_operands(struct ir_insn *insn) {
    struct array     uses = INIT_ARRAY(struct ir_value *);
    struct ir_value *pos;

    for (__u8 j = 0; j < insn->value_num; ++j) {
        pos = &insn->values[j];
        array_push(&uses, &pos);
    }
    if (insn->op == IR_INSN_PHI) {
        struct phi_value *pv_pos2;
        array_for(pv_pos2, insn->phi) {
            pos = &pv_pos2->value;
            array_push(&uses, &pos);
        }
    }
    return uses;
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
    } else if (pos == INSERT_FRONT) {
        list_add_tail(&new_insn->list_ptr, &insn->list_ptr);
    } else {
        CRITICAL("Insert position not available for insn");
    }
}

void insert_at_bb(struct ir_insn *new_insn, struct ir_basic_block *bb, enum insert_position pos) {
    if (pos == INSERT_BACK) {
        list_add_tail(&new_insn->list_ptr, &bb->ir_insn_head);
    } else if (pos == INSERT_FRONT) {
        list_add(&new_insn->list_ptr, &bb->ir_insn_head);
    } else if (pos == INSERT_BACK_BEFORE_JMP) {
        // 1. If no JMP instruction, directly insert at the back
        // 2. If there is a JMP at the end, insert before it
        struct ir_insn *last_insn = get_last_insn(bb);
        if (last_insn) {
            if (is_jmp(last_insn)) {
                // Insert before this insn
                list_add_tail(&new_insn->list_ptr, &last_insn->list_ptr);
            } else {
                // Insert at the back
                list_add_tail(&new_insn->list_ptr, &bb->ir_insn_head);
            }
        } else {
            // Empty
            list_add_tail(&new_insn->list_ptr, &bb->ir_insn_head);
        }
    } else if (pos == INSERT_FRONT_AFTER_PHI){
        // Insert after all PHIs
        struct ir_insn*insn =NULL;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr){
            if (insn->op != IR_INSN_PHI) {
                break;
            }
        }
        if (insn) {
            // Insert before insn
            list_add_tail(&new_insn->list_ptr, &insn->list_ptr);
        }else{
            // No insn
            list_add(&new_insn->list_ptr, &bb->ir_insn_head);
        }
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

struct ir_insn *create_bin_insn_base(struct ir_basic_block *bb, struct ir_value val1,
                                     struct ir_value val2, enum ir_insn_type ty) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = ty;
    new_insn->values[0]      = val1;
    new_insn->values[1]      = val2;
    val_add_user(val1, new_insn);
    val_add_user(val2, new_insn);
    return new_insn;
}

struct ir_insn *create_bin_insn(struct ir_insn *insn, struct ir_value val1, struct ir_value val2,
                                enum ir_insn_type ty, enum insert_position pos) {
    struct ir_insn *new_insn = create_bin_insn_base(insn->parent_bb, val1, val2, ty);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_bin_insn_bb(struct ir_basic_block *bb, struct ir_value val1,
                                   struct ir_value val2, enum ir_insn_type ty,
                                   enum insert_position pos) {
    struct ir_insn *new_insn = create_bin_insn_base(bb, val1, val2, ty);
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

struct ir_insn *create_ja_insn_base(struct ir_basic_block *bb, struct ir_basic_block *to_bb) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_JA;
    new_insn->bb1            = to_bb;
    array_push(&to_bb->users, &new_insn);
    return new_insn;
}

struct ir_insn *create_ja_insn(struct ir_insn *insn, struct ir_basic_block *to_bb,
                               enum insert_position pos) {
    struct ir_insn *new_insn = create_ja_insn_base(insn->parent_bb, to_bb);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_ja_insn_bb(struct ir_basic_block *bb, struct ir_basic_block *to_bb,
                                  enum insert_position pos) {
    struct ir_insn *new_insn = create_ja_insn_base(bb, to_bb);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

struct ir_insn *create_jbin_insn_base(struct ir_basic_block *bb, struct ir_value val1,
                                      struct ir_value val2, struct ir_basic_block *to_bb1,
                                      struct ir_basic_block *to_bb2, enum ir_insn_type ty) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = ty;
    new_insn->values[0]      = val1;
    new_insn->values[1]      = val2;
    new_insn->bb1            = to_bb1;
    new_insn->bb2            = to_bb2;
    val_add_user(val1, new_insn);
    val_add_user(val2, new_insn);
    array_push(&to_bb1->users, &new_insn);
    array_push(&to_bb2->users, &new_insn);
    return new_insn;
}

struct ir_insn *create_jbin_insn(struct ir_insn *insn, struct ir_value val1, struct ir_value val2,
                                 struct ir_basic_block *to_bb1, struct ir_basic_block *to_bb2,
                                 enum ir_insn_type ty, enum insert_position pos) {
    struct ir_insn *new_insn =
        create_jbin_insn_base(insn->parent_bb, val1, val2, to_bb1, to_bb2, ty);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_jbin_insn_bb(struct ir_basic_block *bb, struct ir_value val1,
                                    struct ir_value val2, struct ir_basic_block *to_bb1,
                                    struct ir_basic_block *to_bb2, enum ir_insn_type ty,
                                    enum insert_position pos) {
    struct ir_insn *new_insn = create_jbin_insn_base(bb, val1, val2, to_bb1, to_bb2, ty);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

struct ir_insn *create_ret_insn_base(struct ir_basic_block *bb, struct ir_value val) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_RET;
    new_insn->values[0]      = val;
    val_add_user(val, new_insn);
    return new_insn;
}

struct ir_insn *create_ret_insn(struct ir_insn *insn, struct ir_value val,
                                enum insert_position pos) {
    struct ir_insn *new_insn = create_ret_insn_base(insn->parent_bb, val);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_ret_insn_bb(struct ir_basic_block *bb, struct ir_value val,
                                   enum insert_position pos) {
    struct ir_insn *new_insn = create_ret_insn_base(bb, val);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

int is_jmp(struct ir_insn *insn) {
    return (insn->op >= IR_INSN_JA && insn->op <= IR_INSN_JNE) || insn->op == IR_INSN_RET;
}

int is_void(struct ir_insn *insn) {
    return is_jmp(insn) || insn->op == IR_INSN_STORERAW || insn->op == IR_INSN_STORE;
}
