#include "ir_bb.h"
#include "array.h"
#include "bpf_ir.h"

size_t bb_len(struct ir_basic_block *bb) {
    size_t            len = 0;
    struct list_head *p   = NULL;
    list_for_each(p, &bb->ir_insn_head) {
        len++;
    }
    return len;
}

struct ir_basic_block *create_bb(struct ir_function *fun) {
    struct ir_basic_block *new_bb = __malloc(sizeof(struct ir_basic_block));
    INIT_LIST_HEAD(&new_bb->ir_insn_head);
    array_push(&fun->all_bbs, &new_bb);
    new_bb->user_data = NULL;
    new_bb->preds     = array_init(sizeof(struct ir_insn *));
    new_bb->succs     = array_init(sizeof(struct ir_insn *));
    return new_bb;
}

void push_unique_bb(struct array *bbs, struct ir_basic_block *bb) {
    for (size_t i = 0; i < bbs->num_elem; ++i) {
        if (((struct ir_basic_block **)(bbs->data))[i] == bb) {
            return;
        }
    }
    array_push(bbs, &bb);
}

void connect_bb(struct ir_basic_block *from, struct ir_basic_block *to) {
    push_unique_bb(&from->succs, to);
    push_unique_bb(&to->preds, from);
}

void disconnect_bb(struct ir_basic_block *from, struct ir_basic_block *to) {
    for (size_t i = 0; i < from->succs.num_elem; ++i) {
        if (((struct ir_basic_block **)(from->succs.data))[i] == to) {
            array_erase(&from->succs, i);
            break;
        }
    }
    for (size_t i = 0; i < to->preds.num_elem; ++i) {
        if (((struct ir_basic_block **)(to->preds.data))[i] == from) {
            array_erase(&to->preds, i);
            break;
        }
    }
}

void split_bb(struct ir_function *fun, struct ir_insn *insn) {
    struct ir_basic_block *bb = insn->parent_bb;
    struct ir_basic_block * new_bb = create_bb(fun);
    new_bb->succs = bb->succs;
    bb->succs = array_init(sizeof(struct ir_basic_block *));
    connect_bb(bb, new_bb);
    // Move all instructions after insn to new_bb
    struct list_head *p = insn->list_ptr.next;
    while (p != &bb->ir_insn_head) {
        struct ir_insn *cur = list_entry(p, struct ir_insn, list_ptr);
        p = p->next;
        list_del(&cur->list_ptr);
        list_add_tail(&cur->list_ptr, &new_bb->ir_insn_head);
        cur->parent_bb = new_bb;
    }
}
