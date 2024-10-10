#include <linux/bpf_ir.h>

int bpf_ir_valid_alu_type(enum ir_alu_op_type type)
{
	return type >= IR_ALU_32 && type <= IR_ALU_64;
}

int bpf_ir_valid_vr_type(enum ir_vr_type type)
{
	return type >= IR_VR_TYPE_8 && type <= IR_VR_TYPE_64;
}

/// Reset visited flag and user_data
void bpf_ir_clean_metadata_all(struct ir_function *fun)
{
	for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
		struct ir_basic_block *bb =
			((struct ir_basic_block **)(fun->all_bbs.data))[i];
		bb->_visited = 0;
		bb->_id = -1;
		bb->user_data = NULL;
		struct list_head *p = NULL;
		list_for_each(p, &bb->ir_insn_head) {
			struct ir_insn *insn =
				list_entry(p, struct ir_insn, list_ptr);
			insn->user_data = NULL;
			insn->_insn_id = -1;
			insn->_visited = 0;
		}
	}
}

void bpf_ir_clean_visited(struct ir_function *fun)
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
void bpf_ir_clean_id(struct ir_function *fun)
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

void print_insn_ptr_base(struct bpf_ir_env *env, struct ir_insn *insn)
{
	if (insn->op == IR_INSN_REG) {
		PRINT_LOG(env, "R%u", insn->reg_id);
		return;
	}
	if (insn->op == IR_INSN_FUNCTIONARG) {
		PRINT_LOG(env, "arg%u", insn->fun_arg_id);
		return;
	}
	if (insn->_insn_id == SIZET_MAX) {
		PRINT_LOG(env, "%p", insn);
		return;
	}
	PRINT_LOG(env, "%%%zu", insn->_insn_id);
}

static void print_insn_ptr(struct bpf_ir_env *env, struct ir_insn *insn,
			   void (*print_ir)(struct bpf_ir_env *env,
					    struct ir_insn *))
{
	if (print_ir) {
		print_ir(env, insn);
	} else {
		print_insn_ptr_base(env, insn);
	}
}

void print_bb_ptr(struct bpf_ir_env *env, struct ir_basic_block *insn)
{
	if (insn->_id == SIZE_MAX) {
		PRINT_LOG(env, "b%p", insn);
		return;
	}
	PRINT_LOG(env, "b%zu", insn->_id);
}

static void print_const(struct bpf_ir_env *env, struct ir_value v)
{
	if (v.builtin_const == IR_BUILTIN_NONE) {
		if (v.const_type == IR_ALU_64) {
			PRINT_LOG(env, "0x%llx", v.data.constant_d);
			PRINT_LOG(env, "(64)");
		} else if (v.const_type == IR_ALU_32) {
			PRINT_LOG(env, "0x%x", v.data.constant_d & 0xFFFFFFFF);
			PRINT_LOG(env, "(32)");
		} else {
			PRINT_LOG(env, "(unknown)");
			env->err = -1;
			return;
		}
	} else {
		// Builtin constant
		if (v.builtin_const == IR_BUILTIN_BB_INSN_CNT) {
			PRINT_LOG(env, "__BB_INSN_CNT__");
		}
	}
}

static void print_ir_rawpos(struct bpf_ir_env *env, struct ir_raw_pos pos)
{
	if (pos.valid) {
		PRINT_LOG(env, "[%zu.", pos.pos);
		switch (pos.pos_t) {
		case IR_RAW_POS_IMM:
			PRINT_LOG(env, "imm");
			break;
		case IR_RAW_POS_DST:
			PRINT_LOG(env, "dst");
			break;
		case IR_RAW_POS_SRC:
			PRINT_LOG(env, "src");
			break;
		case IR_RAW_POS_INSN:
			PRINT_LOG(env, "insn");
			break;
		default:
			CRITICAL("UNKNOWN IR RAWPOS")
		}
		PRINT_LOG(env, "]");
	}
}

static void print_ir_value_full(struct bpf_ir_env *env, struct ir_value v,
				void (*print_ir)(struct bpf_ir_env *env,
						 struct ir_insn *))
{
	switch (v.type) {
	case IR_VALUE_INSN:
		print_insn_ptr(env, v.data.insn_d, print_ir);
		break;
	case IR_VALUE_CONSTANT:
		print_const(env, v);
		break;
	case IR_VALUE_CONSTANT_RAWOFF:
		PRINT_LOG(env, "hole(");
		print_const(env, v);
		PRINT_LOG(env, ")");
		break;
	case IR_VALUE_UNDEF:
		PRINT_LOG(env, "undef");
		break;
	default:
		RAISE_ERROR("Unknown IR value type");
	}
	print_ir_rawpos(env, v.raw_pos);
}

void print_ir_value(struct bpf_ir_env *env, struct ir_value v)
{
	print_ir_value_full(env, v, 0);
}

void print_address_value_full(struct bpf_ir_env *env, struct ir_address_value v,
			      void (*print_ir)(struct bpf_ir_env *env,
					       struct ir_insn *))
{
	print_ir_value_full(env, v.value, print_ir);
	if (v.offset != 0) {
		PRINT_LOG(env, "+%d", v.offset);
	}
}

void print_address_value(struct bpf_ir_env *env, struct ir_address_value v)
{
	print_address_value_full(env, v, 0);
}

void print_vr_type(struct bpf_ir_env *env, enum ir_vr_type t)
{
	switch (t) {
	case IR_VR_TYPE_8:
		PRINT_LOG(env, "u8");
		break;
	case IR_VR_TYPE_64:
		PRINT_LOG(env, "u64");
		break;
	case IR_VR_TYPE_16:
		PRINT_LOG(env, "u16");
		break;
	case IR_VR_TYPE_32:
		PRINT_LOG(env, "u32");
		break;
	default:
		CRITICAL("Unknown VR type");
	}
}

static void print_phi_full(struct bpf_ir_env *env, struct array *phi,
			   void (*print_ir)(struct bpf_ir_env *env,
					    struct ir_insn *))
{
	for (size_t i = 0; i < phi->num_elem; ++i) {
		struct phi_value v = ((struct phi_value *)(phi->data))[i];
		PRINT_LOG(env, " <");
		print_bb_ptr(env, v.bb);
		PRINT_LOG(env, " -> ");
		print_ir_value_full(env, v.value, print_ir);
		PRINT_LOG(env, ">");
	}
}

void print_phi(struct bpf_ir_env *env, struct array *phi)
{
	print_phi_full(env, phi, 0);
}

static void print_alu(struct bpf_ir_env *env, struct ir_insn *insn,
		      void (*print_ir)(struct bpf_ir_env *env,
				       struct ir_insn *),
		      const char *str)
{
	PRINT_LOG(env, "%s", str);
	if (insn->alu_op == IR_ALU_64) {
		PRINT_LOG(env, "(64) ");
	} else if (insn->alu_op == IR_ALU_32) {
		PRINT_LOG(env, "(32) ");
	} else {
		PRINT_LOG(env, "(?) ");
	}
	print_ir_value_full(env, insn->values[0], print_ir);
	PRINT_LOG(env, ", ");
	print_ir_value_full(env, insn->values[1], print_ir);
	PRINT_LOG(env, ", ");
}

static void print_imm64ld_op(struct bpf_ir_env *env,
			     enum ir_loadimm_extra_type ty)
{
	switch (ty) {
	case IR_LOADIMM_IMM64:
		PRINT_LOG(env, "imm64");
		break;
	case IR_LOADIMM_MAP_BY_FD:
		PRINT_LOG(env, "map_fd");
		break;
	case IR_LOADIMM_MAP_VAL_FD:
		PRINT_LOG(env, "map_val_fd");
		break;
	case IR_LOADIMM_VAR_ADDR:
		PRINT_LOG(env, "var_addr");
		break;
	case IR_LOADIMM_CODE_ADDR:
		PRINT_LOG(env, "code_addr");
		break;
	case IR_LOADIMM_MAP_BY_IDX:
		PRINT_LOG(env, "map_idx");
		break;
	case IR_LOADIMM_MAP_VAL_IDX:
		PRINT_LOG(env, "map_val_idx");
		break;
	default:
		CRITICAL("Error");
	}
}

static void print_cond_jmp(struct bpf_ir_env *env, struct ir_insn *insn,
			   void (*print_ir)(struct bpf_ir_env *env,
					    struct ir_insn *),
			   const char *name)
{
	print_alu(env, insn, print_ir, name);
	print_bb_ptr(env, insn->bb1);
	PRINT_LOG(env, "/");
	print_bb_ptr(env, insn->bb2);
}

/**
    Print the IR insn
 */
void print_ir_insn_full(struct bpf_ir_env *env, struct ir_insn *insn,
			void (*print_ir)(struct bpf_ir_env *env,
					 struct ir_insn *))
{
	switch (insn->op) {
	case IR_INSN_ALLOC:
		PRINT_LOG(env, "alloc ");
		print_vr_type(env, insn->vr_type);
		break;
	case IR_INSN_ALLOCARRAY:
		PRINT_LOG(env, "allocarray <");
		print_vr_type(env, insn->vr_type);
		PRINT_LOG(env, " x %u>", insn->array_num);
		break;
	case IR_INSN_STORE:
		PRINT_LOG(env, "store ");
		print_ir_value_full(env, insn->values[0], print_ir);
		PRINT_LOG(env, ", ");
		print_ir_value_full(env, insn->values[1], print_ir);
		break;
	case IR_INSN_LOAD:
		PRINT_LOG(env, "load ");
		print_ir_value_full(env, insn->values[0], print_ir);
		break;
	case IR_INSN_LOADRAW:
		PRINT_LOG(env, "loadraw ");
		print_vr_type(env, insn->vr_type);
		PRINT_LOG(env, " ");
		print_address_value_full(env, insn->addr_val, print_ir);
		break;
	case IR_INSN_LOADIMM_EXTRA:
		PRINT_LOG(env, "loadimm(", insn->imm_extra_type);
		print_imm64ld_op(env, insn->imm_extra_type);
		PRINT_LOG(env, ") 0x%llx", insn->imm64);
		break;
	case IR_INSN_STORERAW:
		PRINT_LOG(env, "storeraw ");
		print_vr_type(env, insn->vr_type);
		PRINT_LOG(env, " ");
		print_address_value_full(env, insn->addr_val, print_ir);
		PRINT_LOG(env, " ");
		print_ir_value_full(env, insn->values[0], print_ir);
		break;
	case IR_INSN_GETELEMPTR:
		PRINT_LOG(env, "getelemptr ");
		print_ir_value_full(env, insn->values[1], print_ir);
		PRINT_LOG(env, "+");
		print_ir_value_full(env, insn->values[0], print_ir);
		break;
	case IR_INSN_ADD:
		print_alu(env, insn, print_ir, "add");
		break;
	case IR_INSN_SUB:
		print_alu(env, insn, print_ir, "sub");
		break;
	case IR_INSN_MUL:
		print_alu(env, insn, print_ir, "mul");
		break;
	case IR_INSN_LSH:
		print_alu(env, insn, print_ir, "lsh");
		break;
	case IR_INSN_MOD:
		print_alu(env, insn, print_ir, "mod");
		break;
	case IR_INSN_CALL:
		PRINT_LOG(env, "call __built_in_func_%d(", insn->fid);
		if (insn->value_num >= 1) {
			print_ir_value_full(env, insn->values[0], print_ir);
		}
		for (size_t i = 1; i < insn->value_num; ++i) {
			PRINT_LOG(env, ", ");
			print_ir_value_full(env, insn->values[i], print_ir);
		}
		PRINT_LOG(env, ")");
		break;
	case IR_INSN_RET:
		PRINT_LOG(env, "ret ");
		if (insn->value_num > 0) {
			print_ir_value_full(env, insn->values[0], print_ir);
		}
		break;
	case IR_INSN_JA:
		PRINT_LOG(env, "ja ");
		print_bb_ptr(env, insn->bb1);
		break;
	case IR_INSN_JEQ:
		print_cond_jmp(env, insn, print_ir, "jeq");
		break;
	case IR_INSN_JGT:
		print_cond_jmp(env, insn, print_ir, "jgt");
		break;
	case IR_INSN_JGE:
		print_cond_jmp(env, insn, print_ir, "jge");
		break;
	case IR_INSN_JLT:
		print_cond_jmp(env, insn, print_ir, "jlt");
		break;
	case IR_INSN_JLE:
		print_cond_jmp(env, insn, print_ir, "jle");
		break;
	case IR_INSN_JNE:
		print_cond_jmp(env, insn, print_ir, "jne");
		break;
	case IR_INSN_JSGT:
		print_cond_jmp(env, insn, print_ir, "jsgt");
		break;
	case IR_INSN_JSLT:
		print_cond_jmp(env, insn, print_ir, "jslt");
		break;
	case IR_INSN_PHI:
		PRINT_LOG(env, "phi");
		print_phi_full(env, &insn->phi, print_ir);
		break;
	case IR_INSN_ASSIGN:
		print_ir_value_full(env, insn->values[0], print_ir);
		break;
	default:
		CRITICAL("Unknown IR insn");
	}
	if (insn->raw_pos.valid) {
		PRINT_LOG(env, " // ");
		print_ir_rawpos(env, insn->raw_pos);
	}
}

void print_ir_insn(struct bpf_ir_env *env, struct ir_insn *insn)
{
	print_ir_insn_full(env, insn, 0);
}

void print_raw_ir_insn_full(struct bpf_ir_env *env, struct ir_insn *insn,
			    void (*print_ir)(struct bpf_ir_env *env,
					     struct ir_insn *))
{
	if (print_ir) {
		print_ir(env, insn);
	} else {
		PRINT_LOG(env, "%p", insn);
	}
	PRINT_LOG(env, " = ");
	print_ir_insn_full(env, insn, print_ir);
	PRINT_LOG(env, "\n");
}

void print_raw_ir_insn(struct bpf_ir_env *env, struct ir_insn *insn)
{
	print_raw_ir_insn_full(env, insn, 0);
}

void print_ir_bb_no_rec(
	struct bpf_ir_env *env, struct ir_basic_block *bb,
	void (*post_bb)(struct bpf_ir_env *env, struct ir_basic_block *),
	void (*post_insn)(struct bpf_ir_env *env, struct ir_insn *),
	void (*print_insn_name)(struct bpf_ir_env *env, struct ir_insn *))
{
	PRINT_LOG(env, "b%zu:\n", bb->_id);
	struct list_head *p = NULL;
	list_for_each(p, &bb->ir_insn_head) {
		struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
		if (bpf_ir_is_void(insn)) {
			PRINT_LOG(env, "  ");
		} else {
			PRINT_LOG(env, "  ");
			if (print_insn_name) {
				print_insn_name(env, insn);
			} else {
				PRINT_LOG(env, "%%%zu", insn->_insn_id);
			}
			PRINT_LOG(env, " = ");
		}

		print_ir_insn_full(env, insn, print_insn_name);
		PRINT_LOG(env, "\n");
		if (post_insn) {
			post_insn(env, insn);
		}
	}
	if (post_bb) {
		post_bb(env, bb);
	}
}

void print_ir_bb(struct bpf_ir_env *env, struct ir_basic_block *bb,
		 void (*post_bb)(struct bpf_ir_env *env,
				 struct ir_basic_block *),
		 void (*post_insn)(struct bpf_ir_env *env, struct ir_insn *),
		 void (*print_insn_name)(struct bpf_ir_env *env,
					 struct ir_insn *))
{
	if (bb->_visited) {
		return;
	}
	bb->_visited = 1;
	print_ir_bb_no_rec(env, bb, post_bb, post_insn, print_insn_name);
	for (size_t i = 0; i < bb->succs.num_elem; ++i) {
		struct ir_basic_block *next =
			((struct ir_basic_block **)(bb->succs.data))[i];
		print_ir_bb(env, next, post_bb, post_insn, print_insn_name);
	}
}

void print_ir_prog_reachable(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		print_ir_bb_no_rec(env, bb, NULL, NULL, NULL);
	}
}

void print_raw_ir_bb_full(struct bpf_ir_env *env, struct ir_basic_block *bb,
			  void (*print_ir)(struct bpf_ir_env *env,
					   struct ir_insn *))
{
	PRINT_LOG(env, "b%p:\n", bb);
	struct list_head *p = NULL;
	list_for_each(p, &bb->ir_insn_head) {
		struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
		PRINT_LOG(env, "  ");
		print_raw_ir_insn_full(env, insn, print_ir);
	}
}

void print_raw_ir_bb(struct bpf_ir_env *env, struct ir_basic_block *bb)
{
	print_raw_ir_bb_full(env, bb, 0);
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
		if (!bpf_ir_is_void(insn)) {
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
	bpf_ir_clean_id(fun);
	size_t cnt = 0;
	size_t bb_cnt = 0;
	bpf_ir_clean_visited(fun);
	assign_id(fun->entry, &cnt, &bb_cnt);
	bpf_ir_clean_visited(fun);
}

void print_bb_succ(struct bpf_ir_env *env, struct ir_basic_block *bb)
{
	PRINT_LOG(env, "succs: ");
	struct ir_basic_block **next;
	array_for(next, bb->succs)
	{
		print_bb_ptr(env, *next);
		PRINT_LOG(env, " ");
	}
	PRINT_LOG(env, "\n\n");
}

void print_ir_prog(struct bpf_ir_env *env, struct ir_function *fun)
{
	tag_ir(fun);
	print_ir_bb(env, fun->entry, NULL, NULL, NULL);
}

void print_ir_prog_notag(struct bpf_ir_env *env, struct ir_function *fun)
{
	print_ir_bb(env, fun->entry, NULL, NULL, NULL);
}

void print_ir_dst(struct bpf_ir_env *env, struct ir_insn *insn)
{
	if (!insn_cg(insn)) {
		PRINT_LOG(env, "(?)");
		RAISE_ERROR("NULL userdata found");
	}
	insn = insn_dst(insn);
	if (insn) {
		print_insn_ptr_base(env, insn);
	} else {
		PRINT_LOG(env, "(NULL)");
	}
}

void print_ir_alloc(struct bpf_ir_env *env, struct ir_insn *insn)
{
	insn = insn_dst(insn);
	if (insn) {
		struct ir_insn_cg_extra *extra = insn_cg(insn);
		if (extra->allocated) {
			if (extra->spilled) {
				PRINT_LOG(env, "sp+%d", extra->spilled);
			} else {
				PRINT_LOG(env, "r%u", extra->alloc_reg);
			}
		} else {
			RAISE_ERROR("Not allocated");
		}
	} else {
		PRINT_LOG(env, "(NULL)");
	}
}

void print_ir_prog_advanced(
	struct bpf_ir_env *env, struct ir_function *fun,
	void (*post_bb)(struct bpf_ir_env *env, struct ir_basic_block *),
	void (*post_insn)(struct bpf_ir_env *env, struct ir_insn *),
	void (*print_insn_name)(struct bpf_ir_env *env, struct ir_insn *))
{
	tag_ir(fun);
	print_ir_bb(env, fun->entry, post_bb, post_insn, print_insn_name);
}

void print_ir_insn_err_full(struct bpf_ir_env *env, struct ir_insn *insn,
			    char *msg,
			    void (*print_ir)(struct bpf_ir_env *env,
					     struct ir_insn *))
{
	PRINT_LOG(env, "In BB %zu,\n", insn->parent_bb->_id);
	struct ir_insn *prev = bpf_ir_prev_insn(insn);
	struct ir_insn *next = bpf_ir_next_insn(insn);
	if (prev) {
		PRINT_LOG(env, "  ");
		if (!bpf_ir_is_void(prev)) {
			PRINT_LOG(env, "%%%zu", prev->_insn_id);
			PRINT_LOG(env, " = ");
		}
		print_ir_insn_full(env, prev, print_ir);
		PRINT_LOG(env, "\n");
	} else {
		PRINT_LOG(env, "  (No instruction)\n");
	}
	PRINT_LOG(env, "  ");
	if (!bpf_ir_is_void(insn)) {
		PRINT_LOG(env, "%%%zu", insn->_insn_id);
		PRINT_LOG(env, " = ");
	}
	print_ir_insn_full(env, insn, print_ir);
	PRINT_LOG(env, "         <--- ");
	if (msg) {
		PRINT_LOG(env, "%s\n", msg);
	} else {
		PRINT_LOG(env, "Error\n");
	}
	if (next) {
		PRINT_LOG(env, "  ");
		if (!bpf_ir_is_void(next)) {
			PRINT_LOG(env, "%%%zu", next->_insn_id);
			PRINT_LOG(env, " = ");
		}
		print_ir_insn_full(env, next, print_ir);
		PRINT_LOG(env, "\n");
	} else {
		PRINT_LOG(env, "  (No instruction)\n");
	}
}

void print_ir_insn_err(struct bpf_ir_env *env, struct ir_insn *insn, char *msg)
{
	print_ir_insn_err_full(env, insn, msg, NULL);
}

void print_ir_err_init(struct ir_function *fun)
{
	tag_ir(fun);
}

void print_ir_bb_err(struct bpf_ir_env *env, struct ir_basic_block *bb)
{
	PRINT_LOG(env, "BB %zu encountered an error:\n", bb->_id);
}

void bpf_ir_print_to_log(struct bpf_ir_env *env, char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char buf[200];
	vsprintf(buf, fmt, args);
#ifndef __KERNEL__
	printf("%s", buf); // For debugging purpose, in case there is a SEGFAULT
#endif
	size_t len = strlen(buf);
	if (env->log_pos + len >= BPF_IR_LOG_SIZE) {
		// Clean the log
		env->log_pos = 0;
	}
	memcpy(env->log + env->log_pos, buf, len);
	env->log_pos += len;
	va_end(args);
}

/* Dump env->log */
void bpf_ir_print_log_dbg(struct bpf_ir_env *env)
{
	if (env->log_pos == 0) {
		return;
	}
	env->log[env->log_pos] = '\0';
	PRINT_DBG("----- Begin of Log -----\n");
	// PRINT_DBG("%s", env->log);
	char line[1000];
	size_t i = 0; // Global ptr
	while (i < env->log_pos) {
		size_t j = 0; // Line ptr
		while (i < env->log_pos && j < 1000) {
			line[j++] = env->log[i++];
			if (env->log[i - 1] == '\n') {
				break;
			}
		}
		line[j] = '\0';
		PRINT_DBG("%s", line);
	}
	PRINT_DBG("----- End of Log -----\nLog size: %zu\n", env->log_pos);
	env->log_pos = 0;
}
