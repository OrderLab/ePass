#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/bpf_ir.h>

// TODO: Change this to real function
static const s8 helper_func_arg_num[100] = {
	[0] = 1,  [1] = 1, [2] = 1, [3] = 1, [4] = 1, [5] = 0,
	[6] = -1, // Variable length
	[7] = 1,  [8] = 1
};

// All function passes
static const struct function_pass pre_passes[] = {
	DEF_FUNC_PASS(remove_trivial_phi, "remove_trivial_phi", true),
};

static const struct function_pass post_passes[] = {
	DEF_FUNC_PASS(add_counter, "add_counter", false),
};

static void write_variable(struct bpf_ir_env *env,
			   struct ssa_transform_env *tenv, u8 reg,
			   struct pre_ir_basic_block *bb, struct ir_value val);

static struct ir_value read_variable(struct bpf_ir_env *env,
				     struct ssa_transform_env *tenv, u8 reg,
				     struct pre_ir_basic_block *bb);

static struct ir_insn *add_phi_operands(struct bpf_ir_env *env,
					struct ssa_transform_env *tenv, u8 reg,
					struct ir_insn *insn);

static void add_user(struct bpf_ir_env *env, struct ir_insn *user,
		     struct ir_value val);

static int compare_num(const void *a, const void *b)
{
	struct bb_entrance_info *as = (struct bb_entrance_info *)a;
	struct bb_entrance_info *bs = (struct bb_entrance_info *)b;
	if (as->entrance > bs->entrance) {
		return 1;
	}
	if (as->entrance < bs->entrance) {
		return -1;
	}
	return 0;
}

// Add current_pos --> entrance_pos in bb_entrances
static void add_entrance_info(struct bpf_ir_env *env,
			      const struct bpf_insn *insns,
			      struct array *bb_entrances, size_t entrance_pos,
			      size_t current_pos)
{
	for (size_t i = 0; i < bb_entrances->num_elem; ++i) {
		struct bb_entrance_info *entry =
			((struct bb_entrance_info *)(bb_entrances->data)) + i;
		if (entry->entrance == entrance_pos) {
			// Already has this entrance, add a pred
			bpf_ir_array_push_unique(env, &entry->bb->preds,
						 &current_pos);
			return;
		}
	}
	// New entrance
	struct array preds;
	INIT_ARRAY(&preds, size_t);
	size_t last_pos = entrance_pos - 1;
	u8 code = insns[last_pos].code;
	if (!(BPF_OP(code) == BPF_JA || BPF_OP(code) == BPF_EXIT)) {
		// BPF_EXIT
		bpf_ir_array_push_unique(env, &preds, &last_pos);
	}
	bpf_ir_array_push_unique(env, &preds, &current_pos);
	struct bb_entrance_info new_bb;
	new_bb.entrance = entrance_pos;
	SAFE_MALLOC(new_bb.bb, sizeof(struct pre_ir_basic_block));
	new_bb.bb->preds = preds;
	bpf_ir_array_push(env, bb_entrances, &new_bb);
}

// Return the parent BB of a instruction
static struct pre_ir_basic_block *get_bb_parent(struct array *bb_entrance,
						size_t pos)
{
	size_t bb_id = 0;
	struct bb_entrance_info *bbs =
		(struct bb_entrance_info *)(bb_entrance->data);
	for (size_t i = 1; i < bb_entrance->num_elem; ++i) {
		struct bb_entrance_info *entry = bbs + i;
		if (entry->entrance <= pos) {
			bb_id++;
		} else {
			break;
		}
	}
	return bbs[bb_id].bb;
}

static void init_entrance_info(struct bpf_ir_env *env,
			       struct array *bb_entrances, size_t entrance_pos)
{
	for (size_t i = 0; i < bb_entrances->num_elem; ++i) {
		struct bb_entrance_info *entry =
			((struct bb_entrance_info *)(bb_entrances->data)) + i;
		if (entry->entrance == entrance_pos) {
			// Already has this entrance
			return;
		}
	}
	// New entrance
	struct array preds;
	INIT_ARRAY(&preds, size_t);
	struct bb_entrance_info new_bb;
	new_bb.entrance = entrance_pos;
	SAFE_MALLOC(new_bb.bb, sizeof(struct pre_ir_basic_block));
	new_bb.bb->preds = preds;
	bpf_ir_array_push(env, bb_entrances, &new_bb);
}

static void init_ir_bb(struct bpf_ir_env *env, struct pre_ir_basic_block *bb)
{
	bb->ir_bb = bpf_ir_init_bb_raw();
	if (!bb->ir_bb) {
		env->err = -ENOMEM;
		return;
	}
	bb->ir_bb->_visited = 0;
	bb->ir_bb->user_data = bb;
	for (u8 i = 0; i < MAX_BPF_REG; ++i) {
		bb->incompletePhis[i] = NULL;
	}
}

static s64 to_s64(s32 imm, s32 next_imm)
{
	u64 imml = (u64)imm & 0xFFFFFFFF;
	return ((s64)next_imm << 32) | imml;
}

static void gen_bb(struct bpf_ir_env *env, struct bb_info *ret,
		   const struct bpf_insn *insns, size_t len)
{
	struct array bb_entrance;
	INIT_ARRAY(&bb_entrance, struct bb_entrance_info);
	// First, scan the code to find all the BB entrances
	for (size_t i = 0; i < len; ++i) {
		struct bpf_insn insn = insns[i];
		u8 code = insn.code;
		if (BPF_CLASS(code) == BPF_JMP ||
		    BPF_CLASS(code) == BPF_JMP32) {
			if (BPF_OP(code) == BPF_JA) {
				// Direct Jump
				size_t pos = 0;
				if (BPF_CLASS(code) == BPF_JMP) {
					// JMP class (64 bits)
					// Add offset
					pos = (s16)i + insn.off + 1;
				} else {
					// Impossible by spec
					RAISE_ERROR(
						"BPF_JA only allows JMP class");
				}
				// Add to bb entrance
				// This is one-way control flow
				add_entrance_info(env, insns, &bb_entrance, pos,
						  i);
				CHECK_ERR();
			}
			if ((BPF_OP(code) >= BPF_JEQ &&
			     BPF_OP(code) <= BPF_JSGE) ||
			    (BPF_OP(code) >= BPF_JLT &&
			     BPF_OP(code) <= BPF_JSLE)) {
				// Add offset
				size_t pos = (s16)i + insn.off + 1;
				add_entrance_info(env, insns, &bb_entrance, pos,
						  i);
				CHECK_ERR();
				add_entrance_info(env, insns, &bb_entrance,
						  i + 1, i);
				CHECK_ERR();
			}
			if (BPF_OP(code) == BPF_EXIT) {
				// BPF_EXIT
				if (i + 1 < len) {
					// Not the last instruction
					init_entrance_info(env, &bb_entrance,
							   i + 1);
					CHECK_ERR();
				}
			}
		}
	}

	// Create the first BB (entry block)
	struct bb_entrance_info bb_entry_info;
	bb_entry_info.entrance = 0;
	SAFE_MALLOC(bb_entry_info.bb, sizeof(struct pre_ir_basic_block));
	bb_entry_info.bb->preds = bpf_ir_array_null();
	bpf_ir_array_push(env, &bb_entrance, &bb_entry_info);

	// Sort the BBs
	qsort(bb_entrance.data, bb_entrance.num_elem, bb_entrance.elem_size,
	      &compare_num);
	// Generate real basic blocks

	struct bb_entrance_info *all_bbs =
		((struct bb_entrance_info *)(bb_entrance.data));

	// Print the BB
	// for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
	// 	struct bb_entrance_info entry = all_bbs[i];
	// PRINT_LOG(env, "%ld: %ld\n", entry.entrance,
	// 	  entry.bb->preds.num_elem);
	// }

	// Init preds
	for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
		struct bb_entrance_info *entry = all_bbs + i;
		struct pre_ir_basic_block *real_bb = entry->bb;
		real_bb->id = i;
		INIT_ARRAY(&real_bb->succs, struct pre_ir_basic_block *);
		real_bb->visited = 0;
		real_bb->pre_insns = NULL;
		real_bb->start_pos = entry->entrance;
		real_bb->end_pos = i + 1 < bb_entrance.num_elem ?
					   all_bbs[i + 1].entrance :
					   len;
		real_bb->filled = 0;
		real_bb->sealed = 0;
		real_bb->ir_bb = NULL;
	}

	// Allocate instructions
	for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
		struct pre_ir_basic_block *real_bb = all_bbs[i].bb;
		PRINT_LOG(env, "BB Alloc: [%zu, %zu)\n", real_bb->start_pos,
			  real_bb->end_pos);
		SAFE_MALLOC(real_bb->pre_insns,
			    sizeof(struct pre_ir_insn) *
				    (real_bb->end_pos - real_bb->start_pos));
		size_t bb_pos = 0;
		for (size_t pos = real_bb->start_pos; pos < real_bb->end_pos;
		     ++pos, ++bb_pos) {
			struct bpf_insn insn = insns[pos];
			struct pre_ir_insn new_insn;
			new_insn.opcode = insn.code;
			new_insn.src_reg = insn.src_reg;
			new_insn.dst_reg = insn.dst_reg;
			new_insn.imm = insn.imm;
			new_insn.it = IMM;
			new_insn.imm64 = (u64)insn.imm & 0xFFFFFFFF;
			new_insn.off = insn.off;
			new_insn.pos = pos;
			if (pos + 1 < real_bb->end_pos &&
			    insns[pos + 1].code == 0) {
				new_insn.imm64 =
					to_s64(insn.imm, insns[pos + 1].imm);
				new_insn.it = IMM64;
				pos++;
			}
			real_bb->pre_insns[bb_pos] = new_insn;
		}
		real_bb->len = bb_pos;
	}
	for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
		struct bb_entrance_info *entry = all_bbs + i;

		struct array preds = entry->bb->preds;
		struct array new_preds;
		INIT_ARRAY(&new_preds, struct pre_ir_basic_block *);
		for (size_t j = 0; j < preds.num_elem; ++j) {
			size_t pred_pos = ((size_t *)(preds.data))[j];
			// Get the real parent BB
			struct pre_ir_basic_block *parent_bb =
				get_bb_parent(&bb_entrance, pred_pos);
			// We push the address to the array
			bpf_ir_array_push(env, &new_preds, &parent_bb);
			// Add entry->bb to the succ of parent_bb
			bpf_ir_array_push(env, &parent_bb->succs, &entry->bb);
		}
		bpf_ir_array_free(&preds);
		entry->bb->preds = new_preds;
	}
	// Return the entry BB
	ret->entry = all_bbs[0].bb;
	ret->all_bbs = bb_entrance;
}

static void print_pre_ir_cfg(struct bpf_ir_env *env,
			     struct pre_ir_basic_block *bb)
{
	if (bb->visited) {
		return;
	}
	bb->visited = 1;
	PRINT_LOG(env, "BB %ld:\n", bb->id);
	for (size_t i = 0; i < bb->len; ++i) {
		struct pre_ir_insn insn = bb->pre_insns[i];
		PRINT_LOG(env, "%x %x %llx\n", insn.opcode, insn.imm,
			  insn.imm64);
	}
	PRINT_LOG(env, "preds (%ld): ", bb->preds.num_elem);
	for (size_t i = 0; i < bb->preds.num_elem; ++i) {
		struct pre_ir_basic_block *pred =
			((struct pre_ir_basic_block **)(bb->preds.data))[i];
		PRINT_LOG(env, "%ld ", pred->id);
	}
	PRINT_LOG(env, "\nsuccs (%ld): ", bb->succs.num_elem);
	for (size_t i = 0; i < bb->succs.num_elem; ++i) {
		struct pre_ir_basic_block *succ =
			((struct pre_ir_basic_block **)(bb->succs.data))[i];
		PRINT_LOG(env, "%ld ", succ->id);
	}
	PRINT_LOG(env, "\n\n");
	for (size_t i = 0; i < bb->succs.num_elem; ++i) {
		struct pre_ir_basic_block *succ =
			((struct pre_ir_basic_block **)(bb->succs.data))[i];
		print_pre_ir_cfg(env, succ);
	}
}

static void init_tenv(struct bpf_ir_env *env, struct ssa_transform_env *tenv,
		      struct bb_info info)
{
	for (size_t i = 0; i < MAX_BPF_REG; ++i) {
		INIT_ARRAY(&tenv->currentDef[i], struct bb_val);
	}
	tenv->info = info;
	// Initialize SP
	SAFE_MALLOC(tenv->sp, sizeof(struct ir_insn));
	INIT_ARRAY(&tenv->sp->users, struct ir_insn *);
	tenv->sp->op = IR_INSN_REG;
	tenv->sp->value_num = 0;
	tenv->sp->user_data = NULL;
	tenv->sp->parent_bb = NULL;
	tenv->sp->reg_id = BPF_REG_10;
	write_variable(env, tenv, BPF_REG_10, NULL,
		       bpf_ir_value_insn(tenv->sp));
	// Initialize function argument
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		SAFE_MALLOC(tenv->function_arg[i], sizeof(struct ir_insn));

		INIT_ARRAY(&tenv->function_arg[i]->users, struct ir_insn *);
		tenv->function_arg[i]->op = IR_INSN_FUNCTIONARG;
		tenv->function_arg[i]->fun_arg_id = i;
		tenv->function_arg[i]->user_data = NULL;
		tenv->function_arg[i]->value_num = 0;
		write_variable(env, tenv, BPF_REG_1 + i, NULL,
			       bpf_ir_value_insn(tenv->function_arg[i]));
	}
}

static void seal_block(struct bpf_ir_env *env, struct ssa_transform_env *tenv,
		       struct pre_ir_basic_block *bb)
{
	// Seal a BB
	for (u8 i = 0; i < MAX_BPF_REG; ++i) {
		if (bb->incompletePhis[i]) {
			add_phi_operands(env, tenv, i, bb->incompletePhis[i]);
		}
	}
	bb->sealed = 1;
}

static void write_variable(struct bpf_ir_env *env,
			   struct ssa_transform_env *tenv, u8 reg,
			   struct pre_ir_basic_block *bb, struct ir_value val)
{
	// if (reg >= MAX_BPF_REG - 1) {
	// 	// Stack pointer is read-only
	// 	CRITICAL("Error");
	// }
	// Write a variable to a BB
	struct array *currentDef = &tenv->currentDef[reg];
	// Traverse the array to find if there exists a value in the same BB
	for (size_t i = 0; i < currentDef->num_elem; ++i) {
		struct bb_val *bval = ((struct bb_val *)(currentDef->data)) + i;
		if (bval->bb == bb) {
			// Found
			bval->val = val;
			return;
		}
	}
	// Not found
	struct bb_val new_val;
	new_val.bb = bb;
	new_val.val = val;
	bpf_ir_array_push(env, currentDef, &new_val);
}

static struct ir_insn *add_phi_operands(struct bpf_ir_env *env,
					struct ssa_transform_env *tenv, u8 reg,
					struct ir_insn *insn)
{
	// insn must be a (initialized) PHI instruction
	if (insn->op != IR_INSN_PHI) {
		CRITICAL("Not a PHI node");
	}
	for (size_t i = 0; i < insn->parent_bb->preds.num_elem; ++i) {
		struct ir_basic_block *pred =
			((struct ir_basic_block **)(insn->parent_bb->preds
							    .data))[i];
		struct phi_value phi;
		phi.bb = pred;
		phi.value = read_variable(
			env, tenv, reg,
			(struct pre_ir_basic_block *)pred->user_data);
		add_user(env, insn, phi.value);
		bpf_ir_array_push(env, &pred->users, &insn);
		bpf_ir_array_push(env, &insn->phi, &phi);
	}
	return insn;
}

static struct ir_insn *create_insn(void)
{
	struct ir_insn *insn = malloc_proto(sizeof(struct ir_insn));
	if (!insn) {
		return NULL;
	}
	INIT_ARRAY(&insn->users, struct ir_insn *);
	// Setting the default values
	insn->alu_op = IR_ALU_UNKNOWN;
	insn->vr_type = IR_VR_TYPE_UNKNOWN;
	insn->value_num = 0;
	insn->raw_pos.valid = false;
	return insn;
}

static struct ir_insn *create_insn_back(struct ir_basic_block *bb)
{
	struct ir_insn *insn = create_insn();
	insn->parent_bb = bb;
	list_add_tail(&insn->list_ptr, &bb->ir_insn_head);
	return insn;
}

static struct ir_insn *create_insn_front(struct ir_basic_block *bb)
{
	struct ir_insn *insn = create_insn();
	insn->parent_bb = bb;
	list_add(&insn->list_ptr, &bb->ir_insn_head);
	return insn;
}

static struct ir_value read_variable_recursive(struct bpf_ir_env *env,
					       struct ssa_transform_env *tenv,
					       u8 reg,
					       struct pre_ir_basic_block *bb)
{
	struct ir_value val;
	if (!bb->sealed) {
		// Incomplete CFG
		struct ir_insn *new_insn = create_insn_front(bb->ir_bb);
		new_insn->op = IR_INSN_PHI;
		INIT_ARRAY(&new_insn->phi, struct phi_value);
		bb->incompletePhis[reg] = new_insn;
		val = bpf_ir_value_insn(new_insn);
	} else if (bb->preds.num_elem == 1) {
		val = read_variable(
			env, tenv, reg,
			((struct pre_ir_basic_block **)(bb->preds.data))[0]);
	} else {
		struct ir_insn *new_insn = create_insn_front(bb->ir_bb);
		new_insn->op = IR_INSN_PHI;
		INIT_ARRAY(&new_insn->phi, struct phi_value);
		val = bpf_ir_value_insn(new_insn);
		write_variable(env, tenv, reg, bb, val);
		new_insn = add_phi_operands(env, tenv, reg, new_insn);
		val = bpf_ir_value_insn(new_insn);
	}
	write_variable(env, tenv, reg, bb, val);
	return val;
}

static bool is_variable_defined(struct ssa_transform_env *tenv, u8 reg,
				struct pre_ir_basic_block *bb)
{
	struct bb_val *pos;

	array_for(pos, tenv->currentDef[reg])
	{
		if (pos->bb == bb) {
			return true;
		}
	}
	return false;
}

static struct ir_value read_variable(struct bpf_ir_env *env,
				     struct ssa_transform_env *tenv, u8 reg,
				     struct pre_ir_basic_block *bb)
{
	// Read a variable from a BB
	if (reg == BPF_REG_10) {
		// Stack pointer
		return bpf_ir_value_insn(tenv->sp);
	}
	struct array *currentDef = &tenv->currentDef[reg];
	for (size_t i = 0; i < currentDef->num_elem; ++i) {
		struct bb_val *bval = ((struct bb_val *)(currentDef->data)) + i;
		if (bval->bb == bb) {
			// Found
			return bval->val;
		}
	}
	if (bb == tenv->info.entry) {
		// Entry block, has definitions for r1 to r5
		if (reg > BPF_REG_0 && reg <= MAX_FUNC_ARG) {
			return bpf_ir_value_insn(tenv->function_arg[reg - 1]);
		} else {
			// Invalid Program!
			// Should throw an exception here
			CRITICAL("Invalid program detected!");
		}
	}
	// Not found
	return read_variable_recursive(env, tenv, reg, bb);
}

static enum ir_vr_type to_ir_ld_u(u8 size)
{
	switch (size) {
	case BPF_W:
		return IR_VR_TYPE_32;
	case BPF_H:
		return IR_VR_TYPE_16;
	case BPF_B:
		return IR_VR_TYPE_8;
	case BPF_DW:
		return IR_VR_TYPE_64;
	default:
		CRITICAL("Error");
	}
}

u32 bpf_ir_sizeof_vr_type(enum ir_vr_type type)
{
	switch (type) {
	case IR_VR_TYPE_32:
		return 4;
	case IR_VR_TYPE_16:
		return 2;
	case IR_VR_TYPE_8:
		return 1;
	case IR_VR_TYPE_64:
		return 8;
	default:
		CRITICAL("Error");
	}
}

// User uses val
static void add_user(struct bpf_ir_env *env, struct ir_insn *user,
		     struct ir_value val)
{
	if (val.type == IR_VALUE_INSN) {
		bpf_ir_array_push_unique(env, &val.data.insn_d->users, &user);
	}
}

/**
    Initialize the IR BBs

    Allocate memory and set the preds and succs.
 */
static void init_ir_bbs(struct bpf_ir_env *env, struct ssa_transform_env *tenv)
{
	for (size_t i = 0; i < tenv->info.all_bbs.num_elem; ++i) {
		struct pre_ir_basic_block *bb = ((
			struct bb_entrance_info *)(tenv->info.all_bbs.data))[i]
							.bb;
		init_ir_bb(env, bb);
		CHECK_ERR();
	}
	// Set the preds and succs
	for (size_t i = 0; i < tenv->info.all_bbs.num_elem; ++i) {
		struct pre_ir_basic_block *bb = ((
			struct bb_entrance_info *)(tenv->info.all_bbs.data))[i]
							.bb;
		struct ir_basic_block *irbb = bb->ir_bb;
		for (size_t j = 0; j < bb->preds.num_elem; ++j) {
			struct pre_ir_basic_block *pred =
				((struct pre_ir_basic_block *
					  *)(bb->preds.data))[j];
			bpf_ir_array_push(env, &irbb->preds, &pred->ir_bb);
		}
		for (size_t j = 0; j < bb->succs.num_elem; ++j) {
			struct pre_ir_basic_block *succ =
				((struct pre_ir_basic_block *
					  *)(bb->succs.data))[j];
			bpf_ir_array_push(env, &irbb->succs, &succ->ir_bb);
		}
	}
}

static struct ir_basic_block *
get_ir_bb_from_position(struct ssa_transform_env *tenv, size_t pos)
{
	// Iterate through all the BBs
	for (size_t i = 0; i < tenv->info.all_bbs.num_elem; ++i) {
		struct bb_entrance_info *info = &((
			struct bb_entrance_info *)(tenv->info.all_bbs.data))[i];
		if (info->entrance == pos) {
			return info->bb->ir_bb;
		}
	}
	CRITICAL("Error");
}

static void set_insn_raw_pos(struct ir_insn *insn, size_t pos)
{
	insn->raw_pos.valid = true;
	insn->raw_pos.pos = pos;
	insn->raw_pos.pos_t = IR_RAW_POS_INSN;
}

static void set_value_raw_pos(struct ir_value *val, size_t pos,
			      enum ir_raw_pos_type ty)
{
	val->raw_pos.valid = true;
	val->raw_pos.pos = pos;
	val->raw_pos.pos_t = ty;
}

static struct ir_value get_src_value(struct bpf_ir_env *env,
				     struct ssa_transform_env *tenv,
				     struct pre_ir_basic_block *bb,
				     struct pre_ir_insn insn)
{
	u8 code = insn.opcode;
	if (BPF_SRC(code) == BPF_K) {
		struct ir_value v = bpf_ir_value_const32(insn.imm);
		set_value_raw_pos(&v, insn.pos, IR_RAW_POS_IMM);
		return v;
	} else if (BPF_SRC(code) == BPF_X) {
		struct ir_value v = read_variable(env, tenv, insn.src_reg, bb);
		set_value_raw_pos(&v, insn.pos, IR_RAW_POS_SRC);
		return v;
	} else {
		CRITICAL("Error");
	}
}

static struct ir_insn *
create_alu_bin(struct bpf_ir_env *env, struct ir_basic_block *bb,
	       struct ir_value val1, struct ir_value val2, enum ir_insn_type ty,
	       enum ir_alu_op_type alu_ty)
{
	struct ir_insn *new_insn = create_insn_back(bb);
	new_insn->op = ty;
	new_insn->values[0] = val1;
	new_insn->values[1] = val2;
	new_insn->value_num = 2;
	new_insn->alu_op = alu_ty;
	add_user(env, new_insn, new_insn->values[0]);
	add_user(env, new_insn, new_insn->values[1]);
	return new_insn;
}

static void alu_write(struct bpf_ir_env *env, struct ssa_transform_env *tenv,
		      enum ir_insn_type ty, struct pre_ir_insn insn,
		      struct pre_ir_basic_block *bb, enum ir_alu_op_type alu_ty)
{
	struct ir_insn *new_insn = create_alu_bin(
		env, bb->ir_bb, read_variable(env, tenv, insn.dst_reg, bb),
		get_src_value(env, tenv, bb, insn), ty, alu_ty);
	struct ir_value v = bpf_ir_value_insn(new_insn);
	new_insn->raw_pos.pos = insn.pos;
	set_insn_raw_pos(new_insn, insn.pos);
	set_value_raw_pos(&v, insn.pos, IR_RAW_POS_INSN);
	set_value_raw_pos(&new_insn->values[0], insn.pos, IR_RAW_POS_DST);
	write_variable(env, tenv, insn.dst_reg, bb, v);
}

static void create_cond_jmp(struct bpf_ir_env *env,
			    struct ssa_transform_env *tenv,
			    struct pre_ir_basic_block *bb,
			    struct pre_ir_insn insn, enum ir_insn_type ty,
			    enum ir_alu_op_type alu_ty)
{
	struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
	new_insn->op = ty;
	new_insn->values[0] = read_variable(env, tenv, insn.dst_reg, bb);
	new_insn->values[1] = get_src_value(env, tenv, bb, insn);
	new_insn->value_num = 2;
	new_insn->alu_op = alu_ty;
	add_user(env, new_insn, new_insn->values[0]);
	add_user(env, new_insn, new_insn->values[1]);
	size_t pos = insn.pos + insn.off + 1;
	new_insn->bb1 = get_ir_bb_from_position(tenv, insn.pos + 1);
	new_insn->bb2 = get_ir_bb_from_position(tenv, pos);
	bpf_ir_array_push(env, &new_insn->bb1->users, &new_insn);
	bpf_ir_array_push(env, &new_insn->bb2->users, &new_insn);

	set_insn_raw_pos(new_insn, insn.pos);
	set_value_raw_pos(&new_insn->values[0], insn.pos, IR_RAW_POS_DST);
}

static void transform_bb(struct bpf_ir_env *env, struct ssa_transform_env *tenv,
			 struct pre_ir_basic_block *bb)
{
	PRINT_LOG(env, "Transforming BB%zu\n", bb->id);
	if (bb->sealed) {
		return;
	}
	// Try sealing a BB
	u8 pred_all_filled = 1;
	for (size_t i = 0; i < bb->preds.num_elem; ++i) {
		struct pre_ir_basic_block *pred =
			((struct pre_ir_basic_block **)(bb->preds.data))[i];
		if (!pred->filled) {
			// Not filled
			pred_all_filled = 0;
			break;
		}
	}
	if (pred_all_filled) {
		seal_block(env, tenv, bb);
	}
	if (bb->filled) {
		// Already visited (filled)
		return;
	}
	// Fill the BB
	for (size_t i = 0; i < bb->len; ++i) {
		struct pre_ir_insn insn = bb->pre_insns[i];
		u8 code = insn.opcode;
		if (BPF_CLASS(code) == BPF_ALU ||
		    BPF_CLASS(code) == BPF_ALU64) {
			// ALU class
			enum ir_alu_op_type alu_ty = IR_ALU_UNKNOWN;
			if (BPF_CLASS(code) == BPF_ALU) {
				alu_ty = IR_ALU_32;
			} else {
				alu_ty = IR_ALU_64;
			}
			if (BPF_OP(code) == BPF_ADD) {
				alu_write(env, tenv, IR_INSN_ADD, insn, bb,
					  alu_ty);
			} else if (BPF_OP(code) == BPF_SUB) {
				alu_write(env, tenv, IR_INSN_SUB, insn, bb,
					  alu_ty);
			} else if (BPF_OP(code) == BPF_MUL) {
				alu_write(env, tenv, IR_INSN_MUL, insn, bb,
					  alu_ty);
			} else if (BPF_OP(code) == BPF_MOV) {
				// Do not create instructions
				struct ir_value v =
					get_src_value(env, tenv, bb, insn);
				if (BPF_SRC(code) == BPF_K) {
					// Mov a constant
					// mov64 xx
					// mov xx
					v.const_type = IR_ALU_32;
				}
				write_variable(env, tenv, insn.dst_reg, bb, v);
			} else if (BPF_OP(code) == BPF_LSH) {
				alu_write(env, tenv, IR_INSN_LSH, insn, bb,
					  alu_ty);
			} else if (BPF_OP(code) == BPF_MOD) {
				// dst = (src != 0) ? (dst % src) : dst
				alu_write(env, tenv, IR_INSN_MOD, insn, bb,
					  alu_ty);
			} else {
				// TODO
				RAISE_ERROR("Not supported");
			}
			if (insn.off != 0) {
				RAISE_ERROR("Not supported");
			}

		} else if (BPF_CLASS(code) == BPF_LD &&
			   BPF_MODE(code) == BPF_IMM &&
			   BPF_SIZE(code) == BPF_DW) {
			// 64-bit immediate load
			if (insn.src_reg == 0x0) {
				// immediate value
				struct ir_value v =
					bpf_ir_value_const64(insn.imm64);
				set_value_raw_pos(&v, insn.pos, IR_RAW_POS_IMM);
				write_variable(env, tenv, insn.dst_reg, bb, v);
			} else if (insn.src_reg > 0 && insn.src_reg <= 0x06) {
				// BPF MAP instructions
				struct ir_insn *new_insn =
					create_insn_back(bb->ir_bb);

				new_insn->op = IR_INSN_LOADIMM_EXTRA;
				new_insn->imm_extra_type = insn.src_reg;
				new_insn->imm64 = insn.imm64;
				set_insn_raw_pos(new_insn, insn.pos);
				write_variable(env, tenv, insn.dst_reg, bb,
					       bpf_ir_value_insn(new_insn));
			} else {
				RAISE_ERROR("Not supported");
			}
		} else if (BPF_CLASS(code) == BPF_LDX &&
			   BPF_MODE(code) == BPF_MEMSX) {
			// dst = *(signed size *) (src + offset)
			// https://www.kernel.org/doc/html/v6.6/bpf/standardization/instruction-set.html#sign-extension-load-operations

			struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
			new_insn->op = IR_INSN_LOADRAW;
			struct ir_address_value addr_val;
			addr_val.value =
				read_variable(env, tenv, insn.src_reg, bb);
			add_user(env, new_insn, addr_val.value);
			set_value_raw_pos(&addr_val.value, insn.pos,
					  IR_RAW_POS_SRC);
			addr_val.offset = insn.off;
			new_insn->vr_type = to_ir_ld_u(BPF_SIZE(code));
			new_insn->addr_val = addr_val;

			set_insn_raw_pos(new_insn, insn.pos);
			write_variable(env, tenv, insn.dst_reg, bb,
				       bpf_ir_value_insn(new_insn));
		} else if (BPF_CLASS(code) == BPF_LDX &&
			   BPF_MODE(code) == BPF_MEM) {
			// Regular load
			// dst = *(unsigned size *) (src + offset)
			// https://www.kernel.org/doc/html/v6.6/bpf/standardization/instruction-set.html#regular-load-and-store-operations
			// TODO: use LOAD instead of LOADRAW
			struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
			new_insn->op = IR_INSN_LOADRAW;
			struct ir_address_value addr_val;
			addr_val.value =
				read_variable(env, tenv, insn.src_reg, bb);
			set_value_raw_pos(&addr_val.value, insn.pos,
					  IR_RAW_POS_SRC);
			add_user(env, new_insn, addr_val.value);
			addr_val.offset = insn.off;
			new_insn->vr_type = to_ir_ld_u(BPF_SIZE(code));
			new_insn->addr_val = addr_val;

			set_insn_raw_pos(new_insn, insn.pos);
			write_variable(env, tenv, insn.dst_reg, bb,
				       bpf_ir_value_insn(new_insn));
		} else if (BPF_CLASS(code) == BPF_ST &&
			   BPF_MODE(code) == BPF_MEM) {
			// *(size *) (dst + offset) = imm32
			struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
			new_insn->op = IR_INSN_STORERAW;
			struct ir_address_value addr_val;
			addr_val.value =
				read_variable(env, tenv, insn.dst_reg, bb);
			set_value_raw_pos(&addr_val.value, insn.pos,
					  IR_RAW_POS_DST);
			add_user(env, new_insn, addr_val.value);
			addr_val.offset = insn.off;
			new_insn->vr_type = to_ir_ld_u(BPF_SIZE(code));
			new_insn->addr_val = addr_val;
			new_insn->values[0] = bpf_ir_value_const32(insn.imm);
			new_insn->value_num = 1;
			set_value_raw_pos(&new_insn->values[0], insn.pos,
					  IR_RAW_POS_IMM);
			set_insn_raw_pos(new_insn, insn.pos);
		} else if (BPF_CLASS(code) == BPF_STX &&
			   BPF_MODE(code) == BPF_MEM) {
			// *(size *) (dst + offset) = src
			struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
			new_insn->op = IR_INSN_STORERAW;
			struct ir_address_value addr_val;
			addr_val.value =
				read_variable(env, tenv, insn.dst_reg, bb);
			set_value_raw_pos(&addr_val.value, insn.pos,
					  IR_RAW_POS_DST);
			add_user(env, new_insn, addr_val.value);
			addr_val.offset = insn.off;
			new_insn->vr_type = to_ir_ld_u(BPF_SIZE(code));
			new_insn->addr_val = addr_val;
			new_insn->values[0] =
				read_variable(env, tenv, insn.src_reg, bb);
			set_value_raw_pos(&new_insn->values[0], insn.pos,
					  IR_RAW_POS_SRC);
			new_insn->value_num = 1;
			add_user(env, new_insn, new_insn->values[0]);
			set_insn_raw_pos(new_insn, insn.pos);
		} else if (BPF_CLASS(code) == BPF_JMP ||
			   BPF_CLASS(code) == BPF_JMP32) {
			enum ir_alu_op_type alu_ty = IR_ALU_UNKNOWN;
			if (BPF_CLASS(code) == BPF_JMP) {
				alu_ty = IR_ALU_64;
			} else {
				alu_ty = IR_ALU_32;
			}
			if (BPF_OP(code) == BPF_JA) {
				// Direct Jump
				// PC += offset
				struct ir_insn *new_insn =
					create_insn_back(bb->ir_bb);
				new_insn->op = IR_INSN_JA;
				size_t pos = insn.pos + insn.off + 1;
				new_insn->bb1 =
					get_ir_bb_from_position(tenv, pos);
				set_insn_raw_pos(new_insn, insn.pos);
				bpf_ir_array_push(env, &new_insn->bb1->users,
						  &new_insn);
			} else if (BPF_OP(code) == BPF_EXIT) {
				// Exit
				struct ir_insn *new_insn =
					create_insn_back(bb->ir_bb);
				new_insn->op = IR_INSN_RET;
				new_insn->values[0] =
					read_variable(env, tenv, BPF_REG_0, bb);
				new_insn->value_num = 1;
				set_insn_raw_pos(new_insn, insn.pos);
			} else if (BPF_OP(code) == BPF_JEQ) {
				// PC += offset if dst == src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JEQ, alu_ty);
			} else if (BPF_OP(code) == BPF_JLT) {
				// PC += offset if dst < src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JLT, alu_ty);
			} else if (BPF_OP(code) == BPF_JLE) {
				// PC += offset if dst <= src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JLE, alu_ty);
			} else if (BPF_OP(code) == BPF_JGT) {
				// PC += offset if dst > src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JGT, alu_ty);
			} else if (BPF_OP(code) == BPF_JGE) {
				// PC += offset if dst >= src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JGE, alu_ty);
			} else if (BPF_OP(code) == BPF_JNE) {
				// PC += offset if dst != src
				create_cond_jmp(env, tenv, bb, insn,
						IR_INSN_JNE, alu_ty);
			} else if (BPF_OP(code) == BPF_CALL) {
				// imm is the function id
				struct ir_insn *new_insn =
					create_insn_back(bb->ir_bb);
				set_insn_raw_pos(new_insn, insn.pos);
				new_insn->op = IR_INSN_CALL;
				new_insn->fid = insn.imm;
				if (insn.imm < 0) {
					PRINT_LOG(
						env,
						"Not supported function call\n");
					new_insn->value_num = 0;
				} else {
					if (helper_func_arg_num[insn.imm] < 0) {
						// Variable length, infer from previous instructions
						new_insn->value_num = 0;
						// used[x] means whether there exists a usage of register x + 1
						for (u8 j = 0; j < MAX_FUNC_ARG;
						     ++j) {
							if (is_variable_defined(
								    tenv,
								    j + BPF_REG_1,
								    bb)) {
								new_insn->value_num =
									j +
									BPF_REG_1;
							} else {
								break;
							}
						}
					} else {
						new_insn->value_num =
							helper_func_arg_num
								[insn.imm];
					}
					if (new_insn->value_num >
					    MAX_FUNC_ARG) {
						RAISE_ERROR(
							"Too many arguments");
					}
					for (size_t j = 0;
					     j < new_insn->value_num; ++j) {
						new_insn->values[j] =
							read_variable(
								env, tenv,
								BPF_REG_1 + j,
								bb);
						add_user(env, new_insn,
							 new_insn->values[j]);
					}
				}

				write_variable(env, tenv, BPF_REG_0, bb,
					       bpf_ir_value_insn(new_insn));
			} else {
				// TODO
				RAISE_ERROR("Error");
			}
		} else {
			// TODO
			PRINT_LOG(env, "Class 0x%02x not supported\n",
				  BPF_CLASS(code));
			RAISE_ERROR("Error");
		}
	}
	bb->filled = 1;
	// Finish filling
	for (size_t i = 0; i < bb->succs.num_elem; ++i) {
		struct pre_ir_basic_block *succ =
			((struct pre_ir_basic_block **)(bb->succs.data))[i];
		transform_bb(env, tenv, succ);
		CHECK_ERR();
	}
}

struct ir_insn *bpf_ir_find_ir_insn_by_rawpos(struct ir_function *fun,
					      size_t rawpos)
{
	// Scan through the IR to check if there is an instruction that maps to pos
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->raw_pos.valid) {
				DBGASSERT(insn->raw_pos.pos_t ==
					  IR_RAW_POS_INSN);
				if (insn->raw_pos.pos == rawpos) {
					return insn;
				}
			}
		}
	}
	return NULL;
}

void bpf_ir_free_function(struct ir_function *fun)
{
	for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
		struct ir_basic_block *bb =
			((struct ir_basic_block **)(fun->all_bbs.data))[i];

		bpf_ir_array_free(&bb->preds);
		bpf_ir_array_free(&bb->succs);
		bpf_ir_array_free(&bb->users);
		// Free the instructions
		struct ir_insn *pos = NULL, *n = NULL;
		list_for_each_entry_safe(pos, n, &bb->ir_insn_head, list_ptr) {
			list_del(&pos->list_ptr);
			bpf_ir_array_free(&pos->users);
			if (pos->op == IR_INSN_PHI) {
				bpf_ir_array_free(&pos->phi);
			}
			free_proto(pos);
		}
		free_proto(bb);
	}
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		bpf_ir_array_free(&fun->function_arg[i]->users);
		free_proto(fun->function_arg[i]);
	}
	if (fun->sp) {
		bpf_ir_array_free(&fun->sp->users);
		free_proto(fun->sp);
	}
	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		bpf_ir_array_free(&insn->users);
		free_proto(insn);
	}
	bpf_ir_array_free(&fun->all_bbs);
	bpf_ir_array_free(&fun->reachable_bbs);
	bpf_ir_array_free(&fun->end_bbs);
	bpf_ir_array_free(&fun->cg_info.all_var);
}

static void init_function(struct bpf_ir_env *env, struct ir_function *fun,
			  struct ssa_transform_env *tenv)
{
	fun->arg_num = 1;
	fun->entry = tenv->info.entry->ir_bb;
	fun->sp = tenv->sp;
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		fun->function_arg[i] = tenv->function_arg[i];
	}
	INIT_ARRAY(&fun->all_bbs, struct ir_basic_block *);
	INIT_ARRAY(&fun->reachable_bbs, struct ir_basic_block *);
	INIT_ARRAY(&fun->end_bbs, struct ir_basic_block *);
	INIT_ARRAY(&fun->cg_info.all_var, struct ir_insn *);
	for (size_t i = 0; i < MAX_BPF_REG; ++i) {
		struct array *currentDef = &tenv->currentDef[i];
		bpf_ir_array_free(currentDef);
	}
	for (size_t i = 0; i < tenv->info.all_bbs.num_elem; ++i) {
		struct pre_ir_basic_block *bb = ((
			struct bb_entrance_info *)(tenv->info.all_bbs.data))[i]
							.bb;
		bpf_ir_array_free(&bb->preds);
		bpf_ir_array_free(&bb->succs);
		free_proto(bb->pre_insns);
		bb->ir_bb->user_data = NULL;
		bpf_ir_array_push(env, &fun->all_bbs, &bb->ir_bb);
		free_proto(bb);
	}
	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn;
		SAFE_MALLOC(fun->cg_info.regs[i], sizeof(struct ir_insn));
		// Those should be read-only
		insn = fun->cg_info.regs[i];
		insn->op = IR_INSN_REG;
		insn->parent_bb = NULL;
		INIT_ARRAY(&insn->users, struct ir_insn *);
		insn->value_num = 0;
		insn->reg_id = i;
	}
}

static void run_single_pass(struct bpf_ir_env *env, struct ir_function *fun,
			    const struct function_pass *pass)
{
	bpf_ir_prog_check(env, fun);
	CHECK_ERR();

	PRINT_LOG(env, "\x1B[32m------ Running Pass: %s ------\x1B[0m\n",
		  pass->name);
	pass->pass(env, fun);
	CHECK_ERR();

	// Validate the IR
	bpf_ir_prog_check(env, fun);
	CHECK_ERR();

	print_ir_prog(env, fun);
	CHECK_ERR();
}

static void run_passes(struct bpf_ir_env *env, struct ir_function *fun)
{
	for (size_t i = 0; i < sizeof(pre_passes) / sizeof(pre_passes[0]);
	     ++i) {
		if (pre_passes[i].enabled) {
			run_single_pass(env, fun, &pre_passes[i]);
		} else {
			for (size_t j = 0;
			     j < env->opts.builtin_enable_pass_num; ++j) {
				if (strcmp(env->opts.builtin_enable_passes[j]
						   .name,
					   pre_passes[i].name) == 0) {
					run_single_pass(env, fun,
							&pre_passes[i]);
					break;
				}
			}
		}
		CHECK_ERR();
	}
	for (size_t i = 0; i < env->opts.custom_pass_num; ++i) {
		run_single_pass(env, fun, &env->opts.custom_passes[i]);
	}
	for (size_t i = 0; i < sizeof(post_passes) / sizeof(post_passes[0]);
	     ++i) {
		if (post_passes[i].enabled) {
			run_single_pass(env, fun, &post_passes[i]);
		} else {
			for (size_t j = 0;
			     j < env->opts.builtin_enable_pass_num; ++j) {
				if (strcmp(env->opts.builtin_enable_passes[j]
						   .name,
					   post_passes[i].name) == 0) {
					run_single_pass(env, fun,
							&post_passes[i]);
					break;
				}
			}
		}
		CHECK_ERR();
	}
}

static void print_bpf_insn_simple(struct bpf_ir_env *env,
				  const struct bpf_insn *insn)
{
	if (insn->off < 0) {
		PRINT_LOG(env, "%4x       %x       %x %8x -%8x\n", insn->code,
			  insn->src_reg, insn->dst_reg, insn->imm, -insn->off);
	} else {
		PRINT_LOG(env, "%4x       %x       %x %8x  %8x\n", insn->code,
			  insn->src_reg, insn->dst_reg, insn->imm, insn->off);
	}
}

static void print_bpf_prog(struct bpf_ir_env *env, const struct bpf_insn *insns,
			   size_t len)
{
	if (env->opts.print_mode == BPF_IR_PRINT_DETAIL) {
		PRINT_LOG(env, "      op     src     dst      imm       off\n");
	} else if (env->opts.print_mode == BPF_IR_PRINT_BOTH) {
		PRINT_LOG(env, "  op     src     dst      imm       off\n");
	}
	for (size_t i = 0; i < len; ++i) {
		const struct bpf_insn *insn = &insns[i];
		if (insn->code == 0) {
			continue;
		}
		PRINT_LOG(env, "[%zu] ", i);
		if (env->opts.print_mode == BPF_IR_PRINT_BPF ||
		    env->opts.print_mode == BPF_IR_PRINT_BOTH) {
			bpf_ir_print_bpf_insn(env, insn);
		}
		if (env->opts.print_mode == BPF_IR_PRINT_DETAIL ||
		    env->opts.print_mode == BPF_IR_PRINT_BOTH) {
			print_bpf_insn_simple(env, insn);
		}
	}
}

// Interface implementation

struct ir_function *bpf_ir_lift(struct bpf_ir_env *env,
				const struct bpf_insn *insns, size_t len)
{
	struct bb_info info;
	gen_bb(env, &info, insns, len);
	CHECK_ERR(NULL);

	print_pre_ir_cfg(env, info.entry);
	struct ssa_transform_env trans_env;
	init_tenv(env, &trans_env, info);
	CHECK_ERR(NULL);

	init_ir_bbs(env, &trans_env);
	CHECK_ERR(NULL);

	transform_bb(env, &trans_env, info.entry);
	CHECK_ERR(NULL);

	struct ir_function *fun;
	SAFE_MALLOC_RET_NULL(fun, sizeof(struct ir_function));
	init_function(env, fun, &trans_env);

	return fun;
}

void bpf_ir_run(struct bpf_ir_env *env)
{
	const struct bpf_insn *insns = env->insns;
	size_t len = env->insn_cnt;
	struct ir_function *fun = bpf_ir_lift(env, insns, len);
	CHECK_ERR();

	// Drop env

	bpf_ir_prog_check(env, fun);
	CHECK_ERR();
	print_ir_prog(env, fun);
	PRINT_LOG(env, "Starting IR Passes...\n");
	// Start IR manipulation

	run_passes(env, fun);
	CHECK_ERR();

	// End IR manipulation
	PRINT_LOG(env, "IR Passes Ended!\n");

	bpf_ir_code_gen(env, fun);
	CHECK_ERR();

	// Got the bpf bytecode

	PRINT_LOG(env, "--------------------\nOriginal Program, size %zu:\n",
		  len);
	print_bpf_prog(env, insns, len);
	PRINT_LOG(env, "--------------------\nRewritten Program, size %zu:\n",
		  env->insn_cnt);
	print_bpf_prog(env, env->insns, env->insn_cnt);

	// Free the memory
	bpf_ir_free_function(fun);
}

struct bpf_ir_env *bpf_ir_init_env(struct bpf_ir_opts opts,
				   const struct bpf_insn *insns, size_t len)
{
	struct bpf_ir_env *env = malloc_proto(sizeof(struct bpf_ir_env));
	env->insn_cnt = len;
	env->insns = malloc_proto(sizeof(struct bpf_insn) * len);
	memcpy(env->insns, insns, sizeof(struct bpf_insn) * len);
	env->log_pos = 0;
	env->err = 0;
	env->opts = opts;
	env->verifier_err = -1;
	env->venv = NULL;

	return env;
}

void bpf_ir_free_env(struct bpf_ir_env *env)
{
	free_proto(env->insns);
	free_proto(env);
}
