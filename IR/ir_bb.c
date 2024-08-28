#include "bpf_ir.h"

size_t bb_len(struct ir_basic_block *bb)
{
	size_t len = 0;
	struct list_head *p = NULL;
	list_for_each(p, &bb->ir_insn_head) {
		len++;
	}
	return len;
}

int bb_empty(struct ir_basic_block *bb)
{
	return list_empty(&bb->ir_insn_head);
}

// May have exception
struct ir_basic_block *create_bb(struct ir_function *fun)
{
	struct ir_basic_block *new_bb = init_ir_bb_raw();
	if (!new_bb) {
		return NULL;
	}
	array_push(&fun->all_bbs, &new_bb);
	return new_bb;
}

void connect_bb(struct ir_basic_block *from, struct ir_basic_block *to)
{
	array_push_unique(&from->succs, &to);
	array_push_unique(&to->preds, &from);
}

void disconnect_bb(struct ir_basic_block *from, struct ir_basic_block *to)
{
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

struct ir_basic_block *split_bb(struct ir_function *fun, struct ir_insn *insn)
{
	struct ir_basic_block *bb = insn->parent_bb;
	struct ir_basic_block *new_bb = create_bb(fun);
	struct array old_succs = bb->succs;
	INIT_ARRAY(&bb->succs, struct ir_basic_block *);
	connect_bb(bb, new_bb);
	struct ir_basic_block **pos = NULL;
	array_for(pos, old_succs)
	{
		disconnect_bb(bb, *pos);
		connect_bb(new_bb, *pos);
	}
	array_free(&old_succs);
	// Move all instructions after insn to new_bb
	struct list_head *p = insn->list_ptr.next;
	while (p != &bb->ir_insn_head) {
		struct ir_insn *cur = list_entry(p, struct ir_insn, list_ptr);
		p = p->next;
		list_del(&cur->list_ptr);
		list_add_tail(&cur->list_ptr, &new_bb->ir_insn_head);
		cur->parent_bb = new_bb;
	}
	return new_bb;
}

struct ir_insn *get_last_insn(struct ir_basic_block *bb)
{
	if (bb_empty(bb)) {
		return NULL;
	}
	return list_entry(bb->ir_insn_head.prev, struct ir_insn, list_ptr);
}

struct ir_insn *get_first_insn(struct ir_basic_block *bb)
{
	if (bb_empty(bb)) {
		return NULL;
	}
	return list_entry(bb->ir_insn_head.next, struct ir_insn, list_ptr);
}

struct ir_bb_cg_extra *bb_cg(struct ir_basic_block *bb)
{
	return bb->user_data;
}
