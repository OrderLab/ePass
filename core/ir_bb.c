// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

size_t bpf_ir_bb_len(struct ir_basic_block *bb)
{
	size_t len = 0;
	struct list_head *p = NULL;
	list_for_each(p, &bb->ir_insn_head) {
		len++;
	}
	return len;
}

int bpf_ir_bb_empty(struct ir_basic_block *bb)
{
	return list_empty(&bb->ir_insn_head);
}

// May have exception
struct ir_basic_block *bpf_ir_init_bb_raw(void)
{
	struct ir_basic_block *new_bb =
		malloc_proto(sizeof(struct ir_basic_block));
	if (!new_bb) {
		return NULL;
	}
	INIT_LIST_HEAD(&new_bb->ir_insn_head);
	new_bb->user_data = NULL;
	INIT_ARRAY(&new_bb->preds, struct ir_basic_block *);
	INIT_ARRAY(&new_bb->succs, struct ir_basic_block *);
	new_bb->flag = 0;
	return new_bb;
}

// May have exception
struct ir_basic_block *bpf_ir_create_bb(struct bpf_ir_env *env,
					struct ir_function *fun)
{
	struct ir_basic_block *new_bb = bpf_ir_init_bb_raw();
	if (!new_bb) {
		return NULL;
	}
	bpf_ir_array_push(env, &fun->all_bbs, &new_bb);
	return new_bb;
}

void bpf_ir_connect_bb(struct bpf_ir_env *env, struct ir_basic_block *from,
		       struct ir_basic_block *to)
{
	bpf_ir_array_push_unique(env, &from->succs, &to);
	bpf_ir_array_push_unique(env, &to->preds, &from);
}

void bpf_ir_disconnect_bb(struct ir_basic_block *from,
			  struct ir_basic_block *to)
{
	for (size_t i = 0; i < from->succs.num_elem; ++i) {
		if (((struct ir_basic_block **)(from->succs.data))[i] == to) {
			bpf_ir_array_erase(&from->succs, i);
			break;
		}
	}
	for (size_t i = 0; i < to->preds.num_elem; ++i) {
		if (((struct ir_basic_block **)(to->preds.data))[i] == from) {
			bpf_ir_array_erase(&to->preds, i);
			break;
		}
	}
}

struct ir_basic_block *bpf_ir_split_bb(struct bpf_ir_env *env,
				       struct ir_function *fun,
				       struct ir_insn *insn,
				       enum insert_position insert_pos)
{
	struct ir_basic_block *bb = insn->parent_bb;
	struct ir_basic_block *new_bb = bpf_ir_create_bb(env, fun);
	CHECK_ERR(NULL);
	struct array old_succs = bb->succs;
	INIT_ARRAY(&bb->succs, struct ir_basic_block *);
	bpf_ir_connect_bb(env, bb, new_bb);
	struct ir_basic_block **pos = NULL;
	array_for(pos, old_succs)
	{
		bpf_ir_disconnect_bb(bb, *pos);
		bpf_ir_connect_bb(env, new_bb, *pos);
	}
	bpf_ir_array_free(&old_succs);
	// Move all instructions after insn to new_bb
	struct list_head *p;
	if (insert_pos == INSERT_FRONT) {
		p = &insn->list_ptr;
	} else if (insert_pos == INSERT_BACK) {
		p = insn->list_ptr.next;
	} else {
		RAISE_ERROR_RET("Unknown insert position", NULL);
	}
	if (p == &bb->ir_insn_head) {
		RAISE_ERROR_RET("Cannot split at the end/start of a BB", NULL);
	}
	while (p != &bb->ir_insn_head) {
		struct ir_insn *cur = list_entry(p, struct ir_insn, list_ptr);
		p = p->next;
		list_del(&cur->list_ptr);
		list_add_tail(&cur->list_ptr, &new_bb->ir_insn_head);
		cur->parent_bb = new_bb;
	}
	return new_bb;
}

struct ir_insn *bpf_ir_get_last_insn(struct ir_basic_block *bb)
{
	if (bpf_ir_bb_empty(bb)) {
		return NULL;
	}
	return list_entry(bb->ir_insn_head.prev, struct ir_insn, list_ptr);
}

struct ir_insn *bpf_ir_get_first_insn(struct ir_basic_block *bb)
{
	if (bpf_ir_bb_empty(bb)) {
		return NULL;
	}
	return list_entry(bb->ir_insn_head.next, struct ir_insn, list_ptr);
}

struct ir_bb_cg_extra *bpf_ir_bb_cg(struct ir_basic_block *bb)
{
	return bb->user_data;
}

void bpf_ir_bb_create_error_block(struct bpf_ir_env *env,
				  struct ir_function *fun, struct ir_insn *insn,
				  enum insert_position insert_pos,
				  struct ir_basic_block **dst_err_bb,
				  struct ir_basic_block **dst_new_bb)
{
	struct ir_basic_block *bb = insn->parent_bb;

	struct ir_basic_block *new_bb =
		bpf_ir_split_bb(env, fun, insn, insert_pos);
	CHECK_ERR();
	struct ir_basic_block *err_bb = bpf_ir_create_bb(env, fun);
	CHECK_ERR();
	bpf_ir_create_throw_insn_bb(env, err_bb, INSERT_BACK);
	bpf_ir_connect_bb(env, bb, err_bb);
	*dst_err_bb = err_bb;
	*dst_new_bb = new_bb;
}
