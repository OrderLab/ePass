#include "ir_insn.h"
#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_bb.h"
#include "list.h"
#include "ir_helper.h"

struct ir_insn *create_insn_base(struct ir_basic_block *bb) {
    struct ir_insn *new_insn = __malloc(sizeof(struct ir_insn));
    new_insn->parent_bb      = bb;
    new_insn->users          = INIT_ARRAY(struct ir_insn *);
    new_insn->value_num      = 0;
    return new_insn;
}

struct ir_insn *create_insn_base_cg(struct ir_basic_block *bb) {
    struct ir_insn *new_insn = create_insn_base(bb);
    init_insn_cg(new_insn);
    insn_cg(new_insn)->dst = new_insn;
    return new_insn;
}

void replace_operand(struct ir_insn *insn, struct ir_value v1, struct ir_value v2) {
    // Replace v1 with v2 in insn
    if (v1.type == IR_VALUE_INSN) {
        // Remove user from v1
        val_remove_user(v1, insn);
    }
    if (v2.type == IR_VALUE_INSN) {
        val_add_user(v2, insn);
    }
}

void replace_all_usage(struct ir_insn *insn, struct ir_value rep) {
    struct ir_insn **pos;
    struct array     users = insn->users;
    insn->users            = INIT_ARRAY(struct ir_insn *);
    array_for(pos, users) {
        struct ir_insn   *user     = *pos;
        struct array      operands = get_operands(user);
        struct ir_value **pos2;
        array_for(pos2, operands) {
            if ((*pos2)->type == IR_VALUE_INSN && (*pos2)->data.insn_d == insn) {
                // Match, replace
                **pos2 = rep;
                val_add_user(rep, user);
            }
        }
        array_free(&operands);
    }
    array_free(&users);
}

void replace_all_usage_except(struct ir_insn *insn, struct ir_value rep, struct ir_insn *except) {
    struct ir_insn **pos;
    struct array     users = insn->users;
    insn->users            = INIT_ARRAY(struct ir_insn *);
    array_for(pos, users) {
        struct ir_insn *user = *pos;
        if (user == except) {
            array_push(&insn->users, &user);
            continue;
        }
        struct array      operands = get_operands(user);
        struct ir_value **pos2;
        array_for(pos2, operands) {
            if ((*pos2)->type == IR_VALUE_INSN && (*pos2)->data.insn_d == insn) {
                // Match, replace
                **pos2 = rep;
                val_add_user(rep, user);
            }
        }
        array_free(&operands);
    }
    array_free(&users);
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

void erase_insn_raw(struct ir_insn *insn) {
    list_del(&insn->list_ptr);
    __free(insn);
}

void erase_insn(struct ir_insn *insn) {
    // TODO: remove users
    struct array      operands = get_operands(insn);
    struct ir_value **pos2;
    array_for(pos2, operands) {
        val_remove_user((**pos2), insn);
    }
    array_free(&operands);
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
    } else if (pos == INSERT_FRONT_AFTER_PHI) {
        // Insert after all PHIs
        struct ir_insn *insn = NULL;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            if (insn->op != IR_INSN_PHI) {
                break;
            }
        }
        if (insn) {
            // Insert before insn
            list_add_tail(&new_insn->list_ptr, &insn->list_ptr);
        } else {
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

void val_remove_user(struct ir_value val, struct ir_insn *user) {
    if (val.type != IR_VALUE_INSN) {
        return;
    }
    struct array *arr = &val.data.insn_d->users;
    for (size_t i = 0; i < arr->num_elem; ++i) {
        struct ir_insn *pos = ((struct ir_insn **)(arr->data))[i];
        if (pos == user) {
            array_erase(arr, i);
            return;
        }
    }
    printf("Warning: User not found in the users\n");
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
    struct ir_value nv       = ir_value_insn(insn);
    new_insn->values[0]      = nv;
    new_insn->values[1]      = val;
    new_insn->value_num      = 2;
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
    new_insn->value_num = 1;
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
    new_insn->value_num = 2;
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
    if (prev == &insn->parent_bb->ir_insn_head) {
        return NULL;
    }
    return list_entry(prev, struct ir_insn, list_ptr);
}

struct ir_insn *next_insn(struct ir_insn *insn) {
    struct list_head *next = insn->list_ptr.next;
    if (next == &insn->parent_bb->ir_insn_head) {
        return NULL;
    }
    return list_entry(next, struct ir_insn, list_ptr);
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
    new_insn->value_num = 2;
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
    new_insn->value_num      = 1;
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

struct ir_insn *create_assign_insn_base(struct ir_basic_block *bb, struct ir_value val) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_ASSIGN;
    new_insn->values[0]      = val;
    new_insn->value_num      = 1;
    val_add_user(val, new_insn);
    return new_insn;
}

struct ir_insn *create_assign_insn(struct ir_insn *insn, struct ir_value val,
                                   enum insert_position pos) {
    struct ir_insn *new_insn = create_assign_insn_base(insn->parent_bb, val);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_assign_insn_bb(struct ir_basic_block *bb, struct ir_value val,
                                      enum insert_position pos) {
    struct ir_insn *new_insn = create_assign_insn_base(bb, val);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

struct ir_insn *create_assign_insn_base_cg(struct ir_basic_block *bb, struct ir_value val) {
    struct ir_insn *new_insn = create_insn_base_cg(bb);
    new_insn->op             = IR_INSN_ASSIGN;
    new_insn->values[0]      = val;
    new_insn->value_num      = 1;
    val_add_user(val, new_insn);
    return new_insn;
}

struct ir_insn *create_assign_insn_cg(struct ir_insn *insn, struct ir_value val,
                                      enum insert_position pos) {
    struct ir_insn *new_insn = create_assign_insn_base_cg(insn->parent_bb, val);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_assign_insn_bb_cg(struct ir_basic_block *bb, struct ir_value val,
                                         enum insert_position pos) {
    struct ir_insn *new_insn = create_assign_insn_base_cg(bb, val);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

struct ir_insn *create_phi_insn_base(struct ir_basic_block *bb) {
    struct ir_insn *new_insn = create_insn_base(bb);
    new_insn->op             = IR_INSN_PHI;
    new_insn->phi            = INIT_ARRAY(struct phi_value);
    return new_insn;
}

struct ir_insn *create_phi_insn(struct ir_insn *insn, enum insert_position pos) {
    struct ir_insn *new_insn = create_phi_insn_base(insn->parent_bb);
    insert_at(new_insn, insn, pos);
    return new_insn;
}

struct ir_insn *create_phi_insn_bb(struct ir_basic_block *bb, enum insert_position pos) {
    struct ir_insn *new_insn = create_phi_insn_base(bb);
    insert_at_bb(new_insn, bb, pos);
    return new_insn;
}

void phi_add_operand(struct ir_insn *insn, struct ir_basic_block *bb, struct ir_value val) {
    // Make sure that bb is a pred of insn parent BB
    struct phi_value pv;
    pv.value = val;
    pv.bb    = bb;
    array_push(&insn->phi, &pv);
    val_add_user(val, insn);
}
