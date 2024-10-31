// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

#define RINGBUF_RESERVE 0x83
#define RINGBUF_SUBMIT 0x84
#define RINGBUF_DISCARD 0x85

struct bb_extra {
	struct array gen;
	struct array kill;
	struct array in;
	struct array out;
};

static void init_new_bb(struct bpf_ir_env *env, struct ir_basic_block *bb)
{
	SAFE_MALLOC(bb->user_data, sizeof(struct bb_extra));
	struct bb_extra *extra = bb->user_data;
	INIT_ARRAY(&extra->gen, struct ir_insn *);
	INIT_ARRAY(&extra->kill, struct ir_insn *);
	INIT_ARRAY(&extra->in, struct ir_insn *);
	INIT_ARRAY(&extra->out, struct ir_insn *);
}

static void free_bb_extra(struct ir_basic_block *bb)
{
	if (bb->user_data == NULL) {
		return;
	}
	struct bb_extra *extra = bb->user_data;
	bpf_ir_array_free(&extra->gen);
	bpf_ir_array_free(&extra->kill);
	bpf_ir_array_free(&extra->in);
	bpf_ir_array_free(&extra->out);
	free_proto(bb->user_data);
	bb->user_data = NULL;
}

static bool array_contains(struct array *arr, struct ir_insn *insn)
{
	struct ir_insn **pos;
	array_for(pos, (*arr))
	{
		if (*pos == insn) {
			return true;
		}
	}
	return false;
}

static bool equal_set(struct array *a, struct array *b)
{
	if (a->num_elem != b->num_elem) {
		return false;
	}
	struct ir_insn **pos;
	array_for(pos, (*a))
	{
		struct ir_insn *insn = *pos;
		if (!array_contains(b, insn)) {
			return false;
		}
	}
	return true;
}

static struct array array_delta(struct bpf_ir_env *env, struct array *a,
				struct array *b)
{
	struct array res;
	INIT_ARRAY(&res, struct ir_insn *);
	struct ir_insn **pos;
	array_for(pos, (*a))
	{
		struct ir_insn *insn = *pos;
		if (!array_contains(b, insn)) {
			bpf_ir_array_push(env, &res, &insn);
		}
	}
	return res;
}

static struct array array_intersect(struct bpf_ir_env *env, struct array *a,
				    struct array *b)
{
	struct array res;
	INIT_ARRAY(&res, struct ir_insn *);
	struct ir_insn **pos;
	array_for(pos, (*a))
	{
		struct ir_insn *insn = *pos;
		if (array_contains(b, insn)) {
			bpf_ir_array_push(env, &res, &insn);
		}
	}
	return res;
}

void translate_throw_helper(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct array throw_insns;
	INIT_ARRAY(&throw_insns, struct ir_insn *);
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = bpf_ir_get_last_insn(bb);
		if (insn && insn->op == IR_INSN_THROW) {
			bpf_ir_array_push(env, &throw_insns, &insn);
		}
	}

	struct ir_insn **pos2;
	array_for(pos2, throw_insns)
	{
		// Change this to exit with releasing all refs
		struct ir_insn *insn = *pos2;
		struct ir_basic_block *bb = insn->parent_bb;
		struct bb_extra *extra = bb->user_data;

		if (extra->out.num_elem != 0) {
			// Has to release all refs
			struct ir_insn **pos3;
			array_for(pos3, extra->out)
			{
				struct ir_insn *ref_def = *pos3;
				if (ref_def->op == IR_INSN_CALL &&
				    ref_def->fid == RINGBUF_RESERVE) {
					// Insert bpf_ringbuf_discard(x, 0);
					struct ir_insn *callinsn =
						bpf_ir_create_call_insn(
							env, insn,
							RINGBUF_DISCARD,
							INSERT_FRONT);
					bpf_ir_add_call_arg(
						env, callinsn,
						bpf_ir_value_insn(ref_def));
					bpf_ir_add_call_arg(
						env, callinsn,
						bpf_ir_value_const32(0));

				} else {
					RAISE_ERROR(
						"Does not support this type of ref");
				}
			}
		}
		insn->op = IR_INSN_RET;
		insn->value_num = 1;
		insn->values[0] = bpf_ir_value_const32(0);
	}
}

void translate_throw(struct bpf_ir_env *env, struct ir_function *fun,
		     void *param)
{
	// Initialize
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		init_new_bb(env, bb);
		CHECK_ERR();
		struct bb_extra *extra = bb->user_data;

		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_CALL) {
				if (insn->fid == RINGBUF_RESERVE) {
					bpf_ir_array_push(env, &extra->gen,
							  &insn);
				}
				if (insn->fid == RINGBUF_DISCARD ||
				    insn->fid == RINGBUF_SUBMIT) {
					if (insn->values[0].type ==
					    IR_VALUE_INSN) {
						struct ir_insn *arginsn =
							insn->values[0]
								.data.insn_d;
						if (arginsn->op ==
							    IR_INSN_CALL &&
						    arginsn->fid ==
							    RINGBUF_RESERVE) {
							bpf_ir_array_push(
								env,
								&extra->kill,
								&arginsn);
						} else {
							RAISE_ERROR(
								"Does not support this case");
						}
					} else {
						RAISE_ERROR(
							"Does not support this case");
					}
				}
			}
		}
	}

	// Calculate IN & OUT
	// IN(x) = \cap OUT(x.preds)
	// OUT(x) = (IN(x) + GEN(x)) - KILL(x)
	bool changed = true;
	while (changed) {
		changed = false;
		array_for(pos, fun->reachable_bbs)
		{
			struct ir_basic_block *bb = *pos;
			struct bb_extra *extra = bb->user_data;
			struct array old_in = extra->in;
			INIT_ARRAY(&extra->in, struct ir_insn *); // Reset IN
			bool in_null = true;
			struct ir_basic_block **pred;
			array_for(pred, bb->preds)
			{
				struct ir_basic_block *pred_bb = *pred;
				struct bb_extra *pred_extra =
					pred_bb->user_data;
				if (in_null) {
					bpf_ir_array_clone(env, &extra->in,
							   &pred_extra->out);
					in_null = false;
					continue;
				} else {
					struct array new_in = array_intersect(
						env, &extra->in,
						&pred_extra->out);
					bpf_ir_array_free(&extra->in);
					extra->in = new_in;
				}
			}
			// Update OUT
			bpf_ir_array_free(&extra->out);
			bpf_ir_array_clone(env, &extra->out, &extra->in);
			bpf_ir_array_merge(env, &extra->out, &extra->gen);
			struct array kill_delta =
				array_delta(env, &extra->out, &extra->kill);
			bpf_ir_array_free(&extra->out);
			extra->out = kill_delta;

			if (!equal_set(&old_in, &extra->in)) {
				changed = true;
			}
			bpf_ir_array_free(&old_in);
		}
	}

	// tag_ir(fun);

	// array_for(pos, fun->reachable_bbs)
	// {
	// 	struct ir_basic_block *bb = *pos;
	// 	struct bb_extra *extra = bb->user_data;

	// 	PRINT_LOG_DEBUG(
	// 		env,
	// 		"bb %d: gen size: %d, kill size: %d, in: %d, out: %d\n",
	// 		bb->_id, extra->gen.num_elem, extra->kill.num_elem,
	// 		extra->in.num_elem, extra->out.num_elem);
	// }

	translate_throw_helper(env, fun);

	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		free_bb_extra(bb);
		CHECK_ERR();
	}
}
