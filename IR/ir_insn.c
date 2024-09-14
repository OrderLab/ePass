#include <linux/bpf_ir.h>

// May have exception
struct ir_insn *create_insn_base(struct ir_basic_block *bb)
{
	struct ir_insn *new_insn = malloc_proto(sizeof(struct ir_insn));
	if (!new_insn) {
		return NULL;
	}
	new_insn->parent_bb = bb;
	INIT_ARRAY(&new_insn->users, struct ir_insn *);
	new_insn->value_num = 0;
	return new_insn;
}

// May have exception
struct ir_insn *create_insn_base_cg(struct bpf_ir_env *env,
				    struct ir_basic_block *bb)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	if (!new_insn) {
		return NULL;
	}

	bpf_ir_init_insn_cg(env, new_insn);
	CHECK_ERR(NULL);
	insn_cg(new_insn)->dst = new_insn;
	return new_insn;
}

void replace_operand(struct bpf_ir_env *env, struct ir_insn *insn,
		     struct ir_value v1, struct ir_value v2)
{
	// Replace v1 with v2 in insn
	if (v1.type == IR_VALUE_INSN) {
		// Remove user from v1
		val_remove_user(v1, insn);
	}
	if (v2.type == IR_VALUE_INSN) {
		val_add_user(env, v2, insn);
	}
}

void bpf_ir_replace_all_usage(struct bpf_ir_env *env, struct ir_insn *insn,
			      struct ir_value rep)
{
	struct ir_insn **pos;
	struct array users = insn->users;
	INIT_ARRAY(&insn->users, struct ir_insn *);
	array_for(pos, users)
	{
		struct ir_insn *user = *pos;
		struct array operands = bpf_ir_get_operands(env, user);
		struct ir_value **pos2;
		array_for(pos2, operands)
		{
			if ((*pos2)->type == IR_VALUE_INSN &&
			    (*pos2)->data.insn_d == insn) {
				// Match, replace
				**pos2 = rep;
				val_add_user(env, rep, user);
			}
		}
		bpf_ir_array_free(&operands);
	}
	bpf_ir_array_free(&users);
}

void bpf_ir_replace_all_usage_except(struct bpf_ir_env *env,
				     struct ir_insn *insn, struct ir_value rep,
				     struct ir_insn *except)
{
	struct ir_insn **pos;
	struct array users = insn->users;
	INIT_ARRAY(&insn->users, struct ir_insn *);
	array_for(pos, users)
	{
		struct ir_insn *user = *pos;
		if (user == except) {
			bpf_ir_array_push(env, &insn->users, &user);
			continue;
		}
		struct array operands = bpf_ir_get_operands(env, user);
		struct ir_value **pos2;
		array_for(pos2, operands)
		{
			if ((*pos2)->type == IR_VALUE_INSN &&
			    (*pos2)->data.insn_d == insn) {
				// Match, replace
				**pos2 = rep;
				val_add_user(env, rep, user);
			}
		}
		bpf_ir_array_free(&operands);
	}
	bpf_ir_array_free(&users);
}

struct array bpf_ir_get_operands(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct array uses;
	INIT_ARRAY(&uses, struct ir_value *);
	struct ir_value *pos;

	for (u8 j = 0; j < insn->value_num; ++j) {
		pos = &insn->values[j];
		bpf_ir_array_push(env, &uses, &pos);
	}
	if (insn->op == IR_INSN_PHI) {
		struct phi_value *pv_pos2;
		array_for(pv_pos2, insn->phi)
		{
			pos = &pv_pos2->value;
			bpf_ir_array_push(env, &uses, &pos);
		}
	}
	if (insn->op == IR_INSN_LOADRAW || insn->op == IR_INSN_STORERAW) {
		pos = &insn->addr_val.value;
		bpf_ir_array_push(env, &uses, &pos);
	}
	return uses;
}

int bpf_ir_is_last_insn(struct ir_insn *insn)
{
	return insn->parent_bb->ir_insn_head.prev == &insn->list_ptr;
}

void bpf_ir_erase_insn(struct bpf_ir_env *env, struct ir_insn *insn)
{
	if (insn->users.num_elem > 0) {
		struct ir_insn **pos;
		bool fail = false;
		array_for(pos, insn->users)
		{
			if (*pos != insn) {
				fail = true;
				break;
			}
		}
		if (fail) {
			array_for(pos, insn->users)
			{
				print_ir_insn_err(env, *pos, "User");
			}
			print_ir_insn_err(env, insn, "Has users");
			RAISE_ERROR(
				"Cannot erase a instruction that has (non-self) users");
		}
	}
	struct array operands = bpf_ir_get_operands(env, insn);
	CHECK_ERR();
	struct ir_value **pos2;
	array_for(pos2, operands)
	{
		val_remove_user((**pos2), insn);
	}
	bpf_ir_array_free(&operands);
	list_del(&insn->list_ptr);
	bpf_ir_array_free(&insn->users);
	free_proto(insn);
}

void insert_at(struct ir_insn *new_insn, struct ir_insn *insn,
	       enum insert_position pos)
{
	if (pos == INSERT_BACK) {
		list_add(&new_insn->list_ptr, &insn->list_ptr);
	} else if (pos == INSERT_FRONT) {
		list_add_tail(&new_insn->list_ptr, &insn->list_ptr);
	} else {
		CRITICAL("Insert position not available for insn");
	}
}

void insert_at_bb(struct ir_insn *new_insn, struct ir_basic_block *bb,
		  enum insert_position pos)
{
	if (pos == INSERT_BACK) {
		list_add_tail(&new_insn->list_ptr, &bb->ir_insn_head);
	} else if (pos == INSERT_FRONT) {
		list_add(&new_insn->list_ptr, &bb->ir_insn_head);
	} else if (pos == INSERT_BACK_BEFORE_JMP) {
		// 1. If no JMP instruction, directly insert at the back
		// 2. If there is a JMP at the end, insert before it
		struct ir_insn *last_insn = bpf_ir_get_last_insn(bb);
		if (last_insn) {
			if (is_jmp(last_insn)) {
				// Insert before this insn
				list_add_tail(&new_insn->list_ptr,
					      &last_insn->list_ptr);
			} else {
				// Insert at the back
				list_add_tail(&new_insn->list_ptr,
					      &bb->ir_insn_head);
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

struct ir_insn *create_alloc_insn_base(struct ir_basic_block *bb,
				       enum ir_vr_type type)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	new_insn->op = IR_INSN_ALLOC;
	new_insn->vr_type = type;
	return new_insn;
}

struct ir_insn *create_alloc_insn(struct ir_insn *insn, enum ir_vr_type type,
				  enum insert_position pos)
{
	struct ir_insn *new_insn =
		create_alloc_insn_base(insn->parent_bb, type);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *create_alloc_insn_bb(struct ir_basic_block *bb,
				     enum ir_vr_type type,
				     enum insert_position pos)
{
	struct ir_insn *new_insn = create_alloc_insn_base(bb, type);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

void val_remove_user(struct ir_value val, struct ir_insn *user)
{
	if (val.type != IR_VALUE_INSN) {
		return;
	}
	struct array *arr = &val.data.insn_d->users;
	for (size_t i = 0; i < arr->num_elem; ++i) {
		struct ir_insn *pos = ((struct ir_insn **)(arr->data))[i];
		if (pos == user) {
			bpf_ir_array_erase(arr, i);
			return;
		}
	}
	PRINT_DBG("Warning: User not found in the users\n");
}

void val_add_user(struct bpf_ir_env *env, struct ir_value val,
		  struct ir_insn *user)
{
	if (val.type != IR_VALUE_INSN) {
		return;
	}
	bpf_ir_array_push_unique(env, &val.data.insn_d->users, &user);
}

struct ir_insn *create_store_insn_base(struct bpf_ir_env *env,
				       struct ir_basic_block *bb,
				       struct ir_insn *insn,
				       struct ir_value val)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	new_insn->op = IR_INSN_STORE;
	struct ir_value nv = bpf_ir_value_insn(insn);
	new_insn->values[0] = nv;
	new_insn->values[1] = val;
	new_insn->value_num = 2;
	val_add_user(env, nv, new_insn);
	val_add_user(env, val, new_insn);
	return new_insn;
}

struct ir_insn *create_store_insn(struct bpf_ir_env *env, struct ir_insn *insn,
				  struct ir_insn *st_insn, struct ir_value val,
				  enum insert_position pos)
{
	struct ir_insn *new_insn =
		create_store_insn_base(env, insn->parent_bb, st_insn, val);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *create_store_insn_bb(struct bpf_ir_env *env,
				     struct ir_basic_block *bb,
				     struct ir_insn *st_insn,
				     struct ir_value val,
				     enum insert_position pos)
{
	struct ir_insn *new_insn =
		create_store_insn_base(env, bb, st_insn, val);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

struct ir_insn *create_load_insn_base(struct bpf_ir_env *env,
				      struct ir_basic_block *bb,
				      struct ir_value val)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	new_insn->op = IR_INSN_LOAD;
	new_insn->values[0] = val;
	val_add_user(env, val, new_insn);
	new_insn->value_num = 1;
	return new_insn;
}

struct ir_insn *create_load_insn(struct bpf_ir_env *env, struct ir_insn *insn,
				 struct ir_value val, enum insert_position pos)
{
	struct ir_insn *new_insn =
		create_load_insn_base(env, insn->parent_bb, val);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *create_load_insn_bb(struct bpf_ir_env *env,
				    struct ir_basic_block *bb,
				    struct ir_value val,
				    enum insert_position pos)
{
	struct ir_insn *new_insn = create_load_insn_base(env, bb, val);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

struct ir_insn *create_bin_insn_base(struct bpf_ir_env *env,
				     struct ir_basic_block *bb,
				     struct ir_value val1, struct ir_value val2,
				     enum ir_insn_type ty,
				     enum ir_alu_op_type aluty)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	new_insn->op = ty;
	new_insn->values[0] = val1;
	new_insn->values[1] = val2;
	new_insn->alu_op = aluty;
	val_add_user(env, val1, new_insn);
	val_add_user(env, val2, new_insn);
	new_insn->value_num = 2;
	return new_insn;
}

struct ir_insn *create_bin_insn(struct bpf_ir_env *env, struct ir_insn *insn,
				struct ir_value val1, struct ir_value val2,
				enum ir_insn_type ty, enum ir_alu_op_type aluty,
				enum insert_position pos)
{
	struct ir_insn *new_insn = create_bin_insn_base(env, insn->parent_bb,
							val1, val2, ty, aluty);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *create_bin_insn_bb(struct bpf_ir_env *env,
				   struct ir_basic_block *bb,
				   struct ir_value val1, struct ir_value val2,
				   enum ir_insn_type ty,
				   enum ir_alu_op_type aluty,
				   enum insert_position pos)
{
	struct ir_insn *new_insn =
		create_bin_insn_base(env, bb, val1, val2, ty, aluty);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

struct ir_insn *prev_insn(struct ir_insn *insn)
{
	struct list_head *prev = insn->list_ptr.prev;
	if (prev == &insn->parent_bb->ir_insn_head) {
		return NULL;
	}
	return list_entry(prev, struct ir_insn, list_ptr);
}

struct ir_insn *next_insn(struct ir_insn *insn)
{
	struct list_head *next = insn->list_ptr.next;
	if (next == &insn->parent_bb->ir_insn_head) {
		return NULL;
	}
	return list_entry(next, struct ir_insn, list_ptr);
}

struct ir_insn *create_ja_insn_base(struct bpf_ir_env *env,
				    struct ir_basic_block *bb,
				    struct ir_basic_block *to_bb)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	new_insn->op = IR_INSN_JA;
	new_insn->bb1 = to_bb;
	bpf_ir_array_push(env, &to_bb->users, &new_insn);
	return new_insn;
}

struct ir_insn *create_ja_insn(struct bpf_ir_env *env, struct ir_insn *insn,
			       struct ir_basic_block *to_bb,
			       enum insert_position pos)
{
	struct ir_insn *new_insn =
		create_ja_insn_base(env, insn->parent_bb, to_bb);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *create_ja_insn_bb(struct bpf_ir_env *env,
				  struct ir_basic_block *bb,
				  struct ir_basic_block *to_bb,
				  enum insert_position pos)
{
	struct ir_insn *new_insn = create_ja_insn_base(env, bb, to_bb);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

struct ir_insn *
create_jbin_insn_base(struct bpf_ir_env *env, struct ir_basic_block *bb,
		      struct ir_value val1, struct ir_value val2,
		      struct ir_basic_block *to_bb1,
		      struct ir_basic_block *to_bb2, enum ir_insn_type ty,
		      enum ir_alu_op_type aluty)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	new_insn->op = ty;
	new_insn->values[0] = val1;
	new_insn->values[1] = val2;
	new_insn->bb1 = to_bb1;
	new_insn->bb2 = to_bb2;
	new_insn->alu_op = aluty;
	val_add_user(env, val1, new_insn);
	val_add_user(env, val2, new_insn);
	bpf_ir_array_push(env, &to_bb1->users, &new_insn);
	bpf_ir_array_push(env, &to_bb2->users, &new_insn);
	new_insn->value_num = 2;
	return new_insn;
}

struct ir_insn *create_jbin_insn(struct bpf_ir_env *env, struct ir_insn *insn,
				 struct ir_value val1, struct ir_value val2,
				 struct ir_basic_block *to_bb1,
				 struct ir_basic_block *to_bb2,
				 enum ir_insn_type ty,
				 enum ir_alu_op_type aluty,
				 enum insert_position pos)
{
	struct ir_insn *new_insn = create_jbin_insn_base(
		env, insn->parent_bb, val1, val2, to_bb1, to_bb2, ty, aluty);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *
create_jbin_insn_bb(struct bpf_ir_env *env, struct ir_basic_block *bb,
		    struct ir_value val1, struct ir_value val2,
		    struct ir_basic_block *to_bb1,
		    struct ir_basic_block *to_bb2, enum ir_insn_type ty,
		    enum ir_alu_op_type aluty, enum insert_position pos)
{
	struct ir_insn *new_insn = create_jbin_insn_base(
		env, bb, val1, val2, to_bb1, to_bb2, ty, aluty);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

struct ir_insn *create_ret_insn_base(struct bpf_ir_env *env,
				     struct ir_basic_block *bb,
				     struct ir_value val)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	new_insn->op = IR_INSN_RET;
	new_insn->values[0] = val;
	new_insn->value_num = 1;
	val_add_user(env, val, new_insn);
	return new_insn;
}

struct ir_insn *create_ret_insn(struct bpf_ir_env *env, struct ir_insn *insn,
				struct ir_value val, enum insert_position pos)
{
	struct ir_insn *new_insn =
		create_ret_insn_base(env, insn->parent_bb, val);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *create_ret_insn_bb(struct bpf_ir_env *env,
				   struct ir_basic_block *bb,
				   struct ir_value val,
				   enum insert_position pos)
{
	struct ir_insn *new_insn = create_ret_insn_base(env, bb, val);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

// Note. This includes ret instruction
int is_jmp(struct ir_insn *insn)
{
	return (insn->op >= IR_INSN_JA && insn->op <= IR_INSN_JNE) ||
	       insn->op == IR_INSN_RET;
}

int is_cond_jmp(struct ir_insn *insn)
{
	return (insn->op >= IR_INSN_JEQ && insn->op < IR_INSN_PHI);
}

int is_alu(struct ir_insn *insn)
{
	return insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL;
}

int is_void(struct ir_insn *insn)
{
	return is_jmp(insn) || insn->op == IR_INSN_STORERAW ||
	       insn->op == IR_INSN_STORE;
}

struct ir_insn *create_assign_insn_base(struct bpf_ir_env *env,
					struct ir_basic_block *bb,
					struct ir_value val)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	new_insn->op = IR_INSN_ASSIGN;
	new_insn->values[0] = val;
	new_insn->value_num = 1;
	val_add_user(env, val, new_insn);
	return new_insn;
}

struct ir_insn *create_assign_insn(struct bpf_ir_env *env, struct ir_insn *insn,
				   struct ir_value val,
				   enum insert_position pos)
{
	struct ir_insn *new_insn =
		create_assign_insn_base(env, insn->parent_bb, val);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *create_assign_insn_bb(struct bpf_ir_env *env,
				      struct ir_basic_block *bb,
				      struct ir_value val,
				      enum insert_position pos)
{
	struct ir_insn *new_insn = create_assign_insn_base(env, bb, val);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

struct ir_insn *create_assign_insn_base_cg(struct bpf_ir_env *env,
					   struct ir_basic_block *bb,
					   struct ir_value val)
{
	struct ir_insn *new_insn = create_insn_base_cg(env, bb);
	new_insn->op = IR_INSN_ASSIGN;
	new_insn->values[0] = val;
	new_insn->value_num = 1;
	new_insn->vr_type = IR_VR_TYPE_UNKNOWN;
	new_insn->alu_op = IR_ALU_UNKNOWN;
	val_add_user(env, val, new_insn);
	return new_insn;
}

struct ir_insn *create_assign_insn_cg(struct bpf_ir_env *env,
				      struct ir_insn *insn, struct ir_value val,
				      enum insert_position pos)
{
	struct ir_insn *new_insn =
		create_assign_insn_base_cg(env, insn->parent_bb, val);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *create_assign_insn_bb_cg(struct bpf_ir_env *env,
					 struct ir_basic_block *bb,
					 struct ir_value val,
					 enum insert_position pos)
{
	struct ir_insn *new_insn = create_assign_insn_base_cg(env, bb, val);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

struct ir_insn *create_phi_insn_base(struct ir_basic_block *bb)
{
	struct ir_insn *new_insn = create_insn_base(bb);
	new_insn->op = IR_INSN_PHI;
	INIT_ARRAY(&new_insn->phi, struct phi_value);
	return new_insn;
}

struct ir_insn *create_phi_insn(struct ir_insn *insn, enum insert_position pos)
{
	struct ir_insn *new_insn = create_phi_insn_base(insn->parent_bb);
	insert_at(new_insn, insn, pos);
	return new_insn;
}

struct ir_insn *create_phi_insn_bb(struct ir_basic_block *bb,
				   enum insert_position pos)
{
	struct ir_insn *new_insn = create_phi_insn_base(bb);
	insert_at_bb(new_insn, bb, pos);
	return new_insn;
}

void phi_add_operand(struct bpf_ir_env *env, struct ir_insn *insn,
		     struct ir_basic_block *bb, struct ir_value val)
{
	// Make sure that bb is a pred of insn parent BB
	struct phi_value pv;
	pv.value = val;
	pv.bb = bb;
	bpf_ir_array_push(env, &insn->phi, &pv);
	val_add_user(env, val, insn);
}
