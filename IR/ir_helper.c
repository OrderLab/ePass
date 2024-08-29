#include "bpf_ir.h"

int bpf_ir_valid_alu_type(enum ir_alu_type type)
{
	return type >= IR_ALU_32 && type <= IR_ALU_64;
}

int bpf_ir_valid_vr_type(enum ir_vr_type type)
{
	return type >= IR_VR_TYPE_8 && type <= IR_VR_TYPE_64;
}

/// Reset visited flag
void clean_env_all(struct ir_function *fun)
{
	for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
		struct ir_basic_block *bb =
			((struct ir_basic_block **)(fun->all_bbs.data))[i];
		bb->_visited = 0;
		bb->user_data = NULL;
		struct list_head *p = NULL;
		list_for_each(p, &bb->ir_insn_head) {
			struct ir_insn *insn =
				list_entry(p, struct ir_insn, list_ptr);
			insn->user_data = NULL;
			insn->_visited = 0;
		}
	}
}

void clean_env(struct ir_function *fun)
{
	for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
		struct ir_basic_block *bb =
			((struct ir_basic_block **)(fun->all_bbs.data))[i];
		bb->_visited = 0;
		struct list_head *p = NULL;
		list_for_each(p, &bb->ir_insn_head) {
			struct ir_insn *insn =
				list_entry(p, struct ir_insn, list_ptr);
			insn->_visited = 0;
		}
	}
}

/// Reset instruction/BB ID
void clean_tag(struct ir_function *fun)
{
	for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
		struct ir_basic_block *ir_bb =
			((struct ir_basic_block **)(fun->all_bbs.data))[i];
		ir_bb->_id = -1;
		struct list_head *p = NULL;
		list_for_each(p, &ir_bb->ir_insn_head) {
			struct ir_insn *insn =
				list_entry(p, struct ir_insn, list_ptr);
			insn->_insn_id = -1;
		}
	}
}

void print_insn_ptr_base(struct ir_insn *insn)
{
	if (insn->op == IR_INSN_REG) {
		PRINT_LOG("R%u", insn_cg(insn)->alloc_reg);
		return;
	}
	if (insn->op == IR_INSN_FUNCTIONARG) {
		PRINT_LOG("arg%u", insn->fid);
		return;
	}
	if (insn->_insn_id == SIZET_MAX) {
		PRINT_LOG("%p", insn);
		return;
	}
	PRINT_LOG("%%%zu", insn->_insn_id);
}

void print_insn_ptr(struct ir_insn *insn, void (*print_ir)(struct ir_insn *))
{
	if (print_ir) {
		print_ir(insn);
	} else {
		print_insn_ptr_base(insn);
	}
}

void print_bb_ptr(struct ir_basic_block *insn)
{
	if (insn->_id == SIZE_MAX) {
		PRINT_LOG("b%p", insn);
		return;
	}
	PRINT_LOG("b%zu", insn->_id);
}

void print_ir_value_full(struct ir_value v, void (*print_ir)(struct ir_insn *))
{
	switch (v.type) {
	case IR_VALUE_INSN:
		print_insn_ptr(v.data.insn_d, print_ir);
		break;
	case IR_VALUE_STACK_PTR:
		PRINT_LOG("SP");
		break;
	case IR_VALUE_CONSTANT:
		PRINT_LOG("0x%llx", v.data.constant_d);
		break;
	case IR_VALUE_CONSTANT_RAWOFF:
		PRINT_LOG("(hole)");
		break;
	case IR_VALUE_UNDEF:
		PRINT_LOG("undef");
		break;
	default:
		CRITICAL("Unknown IR value type");
	}
}

void print_ir_value(struct ir_value v)
{
	print_ir_value_full(v, 0);
}

void print_address_value_full(struct ir_address_value v,
			      void (*print_ir)(struct ir_insn *))
{
	print_ir_value_full(v.value, print_ir);
	if (v.offset != 0) {
		PRINT_LOG("+%d", v.offset);
	}
}

void print_address_value(struct ir_address_value v)
{
	print_address_value_full(v, 0);
}

void print_vr_type(enum ir_vr_type t)
{
	switch (t) {
	case IR_VR_TYPE_8:
		PRINT_LOG("u8");
		break;
	case IR_VR_TYPE_64:
		PRINT_LOG("u64");
		break;
	case IR_VR_TYPE_16:
		PRINT_LOG("u16");
		break;
	case IR_VR_TYPE_32:
		PRINT_LOG("u32");
		break;
	default:
		CRITICAL("Unknown VR type");
	}
}

void print_phi_full(struct array *phi, void (*print_ir)(struct ir_insn *))
{
	for (size_t i = 0; i < phi->num_elem; ++i) {
		struct phi_value v = ((struct phi_value *)(phi->data))[i];
		PRINT_LOG(" <");
		print_bb_ptr(v.bb);
		PRINT_LOG(" -> ");
		print_ir_value_full(v.value, print_ir);
		PRINT_LOG(">");
	}
}

void print_phi(struct array *phi)
{
	print_phi_full(phi, 0);
}

/**
    Print the IR insn
 */
void print_ir_insn_full(struct ir_insn *insn,
			void (*print_ir)(struct ir_insn *))
{
	switch (insn->op) {
	case IR_INSN_ALLOC:
		PRINT_LOG("alloc ");
		print_vr_type(insn->vr_type);
		break;
	case IR_INSN_STORE:
		PRINT_LOG("store ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		break;
	case IR_INSN_LOAD:
		PRINT_LOG("load ");
		print_ir_value_full(insn->values[0], print_ir);
		break;
	case IR_INSN_LOADRAW:
		PRINT_LOG("loadraw ");
		print_vr_type(insn->vr_type);
		PRINT_LOG(" ");
		print_address_value_full(insn->addr_val, print_ir);
		break;
	case IR_INSN_STORERAW:
		PRINT_LOG("storeraw ");
		print_vr_type(insn->vr_type);
		PRINT_LOG(" ");
		print_address_value_full(insn->addr_val, print_ir);
		PRINT_LOG(" ");
		print_ir_value_full(insn->values[0], print_ir);
		break;
	case IR_INSN_ADD:
		PRINT_LOG("add ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		break;
	case IR_INSN_SUB:
		PRINT_LOG("sub ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		break;
	case IR_INSN_MUL:
		PRINT_LOG("mul ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		break;
	case IR_INSN_CALL:
		PRINT_LOG("call __built_in_func_%d(", insn->fid);
		if (insn->value_num >= 1) {
			print_ir_value_full(insn->values[0], print_ir);
		}
		for (size_t i = 1; i < insn->value_num; ++i) {
			PRINT_LOG(", ");
			print_ir_value_full(insn->values[i], print_ir);
		}
		PRINT_LOG(")");
		break;
	case IR_INSN_RET:
		PRINT_LOG("ret ");
		if (insn->value_num > 0) {
			print_ir_value_full(insn->values[0], print_ir);
		}
		break;
	case IR_INSN_JA:
		PRINT_LOG("ja ");
		print_bb_ptr(insn->bb1);
		break;
	case IR_INSN_JEQ:
		PRINT_LOG("jeq ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		PRINT_LOG(", ");
		print_bb_ptr(insn->bb1);
		PRINT_LOG("/");
		print_bb_ptr(insn->bb2);
		break;
	case IR_INSN_JGT:
		PRINT_LOG("jgt ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		PRINT_LOG(", ");
		print_bb_ptr(insn->bb1);
		PRINT_LOG("/");
		print_bb_ptr(insn->bb2);
		break;
	case IR_INSN_JGE:
		PRINT_LOG("jge ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		PRINT_LOG(", ");
		print_bb_ptr(insn->bb1);
		PRINT_LOG("/");
		print_bb_ptr(insn->bb2);
		break;
	case IR_INSN_JLT:
		PRINT_LOG("jlt ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		PRINT_LOG(", ");
		print_bb_ptr(insn->bb1);
		PRINT_LOG("/");
		print_bb_ptr(insn->bb2);
		break;
	case IR_INSN_JLE:
		PRINT_LOG("jle ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		PRINT_LOG(", ");
		print_bb_ptr(insn->bb1);
		PRINT_LOG("/");
		print_bb_ptr(insn->bb2);
		break;
	case IR_INSN_JNE:
		PRINT_LOG("jne ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		PRINT_LOG(", ");
		print_bb_ptr(insn->bb1);
		PRINT_LOG("/");
		print_bb_ptr(insn->bb2);
		break;
	case IR_INSN_PHI:
		PRINT_LOG("phi");
		print_phi_full(&insn->phi, print_ir);
		break;
	case IR_INSN_LSH:
		PRINT_LOG("lsh ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		break;
	case IR_INSN_MOD:
		PRINT_LOG("mod ");
		print_ir_value_full(insn->values[0], print_ir);
		PRINT_LOG(", ");
		print_ir_value_full(insn->values[1], print_ir);
		break;
	case IR_INSN_ASSIGN:
		print_ir_value_full(insn->values[0], print_ir);
		break;
	default:
		CRITICAL("Unknown IR insn");
	}
}

void print_ir_insn(struct ir_insn *insn)
{
	print_ir_insn_full(insn, 0);
}

void print_raw_ir_insn_full(struct ir_insn *insn,
			    void (*print_ir)(struct ir_insn *))
{
	if (print_ir) {
		print_ir(insn);
	} else {
		PRINT_LOG("%p", insn);
	}
	PRINT_LOG(" = ");
	print_ir_insn_full(insn, print_ir);
	PRINT_LOG("\n");
}

void print_raw_ir_insn(struct ir_insn *insn)
{
	print_raw_ir_insn_full(insn, 0);
}

void print_ir_bb_no_rec(struct ir_basic_block *bb,
			void (*post_bb)(struct ir_basic_block *),
			void (*post_insn)(struct ir_insn *),
			void (*print_insn_name)(struct ir_insn *))
{
	PRINT_LOG("b%zu:\n", bb->_id);
	struct list_head *p = NULL;
	list_for_each(p, &bb->ir_insn_head) {
		struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
		if (is_void(insn)) {
			PRINT_LOG("  ");
		} else {
			PRINT_LOG("  ");
			if (print_insn_name) {
				print_insn_name(insn);
			} else {
				PRINT_LOG("%%%zu", insn->_insn_id);
			}
			PRINT_LOG(" = ");
		}

		print_ir_insn_full(insn, print_insn_name);
		PRINT_LOG("\n");
		if (post_insn) {
			post_insn(insn);
		}
	}
	if (post_bb) {
		post_bb(bb);
	}
}

void print_ir_bb(struct ir_basic_block *bb,
		 void (*post_bb)(struct ir_basic_block *),
		 void (*post_insn)(struct ir_insn *),
		 void (*print_insn_name)(struct ir_insn *))
{
	if (bb->_visited) {
		return;
	}
	bb->_visited = 1;
	print_ir_bb_no_rec(bb, post_bb, post_insn, print_insn_name);
	for (size_t i = 0; i < bb->succs.num_elem; ++i) {
		struct ir_basic_block *next =
			((struct ir_basic_block **)(bb->succs.data))[i];
		print_ir_bb(next, post_bb, post_insn, print_insn_name);
	}
}

void print_ir_prog_reachable(struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		print_ir_bb_no_rec(bb, NULL, NULL, NULL);
	}
}

void print_raw_ir_bb_full(struct ir_basic_block *bb,
			  void (*print_ir)(struct ir_insn *))
{
	PRINT_LOG("b%p:\n", bb);
	struct list_head *p = NULL;
	list_for_each(p, &bb->ir_insn_head) {
		struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
		PRINT_LOG("  ");
		print_raw_ir_insn_full(insn, print_ir);
	}
}

void print_raw_ir_bb(struct ir_basic_block *bb)
{
	print_raw_ir_bb_full(bb, 0);
}

void assign_id(struct ir_basic_block *bb, size_t *cnt, size_t *bb_cnt)
{
	if (bb->_visited) {
		return;
	}
	bb->_visited = 1;
	bb->_id = (*bb_cnt)++;
	struct list_head *p = NULL;
	list_for_each(p, &bb->ir_insn_head) {
		struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
		if (!is_void(insn)) {
			insn->_insn_id = (*cnt)++;
		}
	}
	struct ir_basic_block **next;
	array_for(next, bb->succs)
	{
		assign_id(*next, cnt, bb_cnt);
	}
}

void tag_ir(struct ir_function *fun)
{
	clean_tag(fun);
	size_t cnt = 0;
	size_t bb_cnt = 0;
	clean_env(fun);
	assign_id(fun->entry, &cnt, &bb_cnt);
	clean_env(fun);
}

void print_bb_succ(struct ir_basic_block *bb)
{
	PRINT_LOG("succs: ");
	struct ir_basic_block **next;
	array_for(next, bb->succs)
	{
		print_bb_ptr(*next);
		PRINT_LOG(" ");
	}
	PRINT_LOG("\n\n");
}

void print_ir_prog(struct ir_function *fun)
{
	tag_ir(fun);
	print_ir_bb(fun->entry, NULL, NULL, NULL);
}

void print_ir_dst(struct ir_insn *insn)
{
	insn = insn_dst(insn);
	if (insn) {
		print_insn_ptr_base(insn);
	} else {
		PRINT_LOG("(NULL)");
	}
}

void print_ir_alloc(struct ir_insn *insn)
{
	insn = insn_dst(insn);
	if (insn) {
		struct ir_insn_cg_extra *extra = insn_cg(insn);
		if (extra->allocated) {
			if (extra->spilled) {
				PRINT_LOG("sp-%zu", extra->spilled * 8);
			} else {
				PRINT_LOG("r%u", extra->alloc_reg);
			}
		} else {
			CRITICAL("Not allocated");
		}
	} else {
		PRINT_LOG("(NULL)");
	}
}

void print_ir_prog_advanced(struct ir_function *fun,
			    void (*post_bb)(struct ir_basic_block *),
			    void (*post_insn)(struct ir_insn *),
			    void (*print_insn_name)(struct ir_insn *))
{
	tag_ir(fun);
	print_ir_bb(fun->entry, post_bb, post_insn, print_insn_name);
}

void print_ir_insn_err(struct ir_insn *insn, char *msg)
{
	PRINT_LOG("In BB %zu,\n", insn->parent_bb->_id);
	struct ir_insn *prev = prev_insn(insn);
	struct ir_insn *next = next_insn(insn);
	if (prev) {
		PRINT_LOG("  ");
		if (!is_void(prev)) {
			PRINT_LOG("%%%zu", prev->_insn_id);
			PRINT_LOG(" = ");
		}
		print_ir_insn(prev);
		PRINT_LOG("\n");
	} else {
		PRINT_LOG("  (No instruction)\n");
	}
	PRINT_LOG("  ");
	if (!is_void(insn)) {
		PRINT_LOG("%%%zu", insn->_insn_id);
		PRINT_LOG(" = ");
	}
	print_ir_insn(insn);
	PRINT_LOG("         <--- ");
	if (msg) {
		PRINT_LOG("%s\n", msg);
	} else {
		PRINT_LOG("Error\n");
	}
	if (next) {
		PRINT_LOG("  ");
		if (!is_void(next)) {
			PRINT_LOG("%%%zu", next->_insn_id);
			PRINT_LOG(" = ");
		}
		print_ir_insn(next);
		PRINT_LOG("\n");
	} else {
		PRINT_LOG("  (No instruction)\n");
	}
}

void print_ir_err_init(struct ir_function *fun)
{
	tag_ir(fun);
}

void print_ir_bb_err(struct ir_basic_block *bb)
{
	PRINT_LOG("BB %zu encountered an error:\n", bb->_id);
}
