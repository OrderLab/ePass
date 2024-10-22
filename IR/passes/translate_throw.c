#include <linux/bpf_ir.h>

#define RINGBUF_RESERVE 0x83
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

void translate_throw(struct bpf_ir_env *env, struct ir_function *fun)
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
				if (insn->fid == RINGBUF_DISCARD) {
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
		PRINT_LOG(env, "gen size: %d, kill size: %d\n",
			  extra->gen.num_elem, extra->kill.num_elem);
	}

	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		free_bb_extra(bb);
		CHECK_ERR();
	}
}
