#include <linux/bpf_ir.h>

struct ir_insn *create_alloc_insn_base(struct ir_basic_block *bb,
				       enum ir_vr_type type)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base(bb);
	new_insn->op = IR_INSN_ALLOC;
	new_insn->vr_type = type;
	return new_insn;
}

struct ir_insn *create_store_insn_base(struct bpf_ir_env *env,
				       struct ir_basic_block *bb,
				       struct ir_insn *insn,
				       struct ir_value val)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base(bb);
	new_insn->op = IR_INSN_STORE;
	struct ir_value nv = bpf_ir_value_insn(insn);
	new_insn->values[0] = nv;
	new_insn->values[1] = val;
	new_insn->value_num = 2;
	bpf_ir_val_add_user(env, nv, new_insn);
	bpf_ir_val_add_user(env, val, new_insn);
	return new_insn;
}

struct ir_insn *create_load_insn_base(struct bpf_ir_env *env,
				      struct ir_basic_block *bb,
				      struct ir_value val)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base(bb);
	new_insn->op = IR_INSN_LOAD;
	new_insn->values[0] = val;
	bpf_ir_val_add_user(env, val, new_insn);
	new_insn->value_num = 1;
	return new_insn;
}

struct ir_insn *create_bin_insn_base(struct bpf_ir_env *env,
				     struct ir_basic_block *bb,
				     struct ir_value val1, struct ir_value val2,
				     enum ir_insn_type ty,
				     enum ir_alu_op_type aluty)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base(bb);
	new_insn->op = ty;
	new_insn->values[0] = val1;
	new_insn->values[1] = val2;
	new_insn->alu_op = aluty;
	bpf_ir_val_add_user(env, val1, new_insn);
	bpf_ir_val_add_user(env, val2, new_insn);
	new_insn->value_num = 2;
	return new_insn;
}

struct ir_insn *create_ja_insn_base(struct bpf_ir_env *env,
				    struct ir_basic_block *bb,
				    struct ir_basic_block *to_bb)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base(bb);
	new_insn->op = IR_INSN_JA;
	new_insn->bb1 = to_bb;
	bpf_ir_array_push(env, &to_bb->users, &new_insn);
	return new_insn;
}

struct ir_insn *
create_jbin_insn_base(struct bpf_ir_env *env, struct ir_basic_block *bb,
		      struct ir_value val1, struct ir_value val2,
		      struct ir_basic_block *to_bb1,
		      struct ir_basic_block *to_bb2, enum ir_insn_type ty,
		      enum ir_alu_op_type aluty)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base(bb);
	new_insn->op = ty;
	new_insn->values[0] = val1;
	new_insn->values[1] = val2;
	new_insn->bb1 = to_bb1;
	new_insn->bb2 = to_bb2;
	new_insn->alu_op = aluty;
	bpf_ir_val_add_user(env, val1, new_insn);
	bpf_ir_val_add_user(env, val2, new_insn);
	bpf_ir_array_push(env, &to_bb1->users, &new_insn);
	bpf_ir_array_push(env, &to_bb2->users, &new_insn);
	new_insn->value_num = 2;
	return new_insn;
}

struct ir_insn *create_ret_insn_base(struct bpf_ir_env *env,
				     struct ir_basic_block *bb,
				     struct ir_value val)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base(bb);
	new_insn->op = IR_INSN_RET;
	new_insn->values[0] = val;
	new_insn->value_num = 1;
	bpf_ir_val_add_user(env, val, new_insn);
	return new_insn;
}

struct ir_insn *create_assign_insn_base(struct bpf_ir_env *env,
					struct ir_basic_block *bb,
					struct ir_value val)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base(bb);
	new_insn->op = IR_INSN_ASSIGN;
	new_insn->values[0] = val;
	new_insn->value_num = 1;
	bpf_ir_val_add_user(env, val, new_insn);
	return new_insn;
}

struct ir_insn *create_assign_insn_base_cg(struct bpf_ir_env *env,
					   struct ir_basic_block *bb,
					   struct ir_value val)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base_cg(env, bb);
	new_insn->op = IR_INSN_ASSIGN;
	new_insn->values[0] = val;
	new_insn->value_num = 1;
	new_insn->vr_type = IR_VR_TYPE_UNKNOWN;
	new_insn->alu_op = IR_ALU_UNKNOWN;
	bpf_ir_val_add_user(env, val, new_insn);
	return new_insn;
}

struct ir_insn *create_phi_insn_base(struct ir_basic_block *bb)
{
	struct ir_insn *new_insn = bpf_ir_create_insn_base(bb);
	new_insn->op = IR_INSN_PHI;
	INIT_ARRAY(&new_insn->phi, struct phi_value);
	return new_insn;
}
