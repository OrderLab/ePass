// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>
#include "ir_cg.h"

// Normalization

static void bpf_ir_free_insn_cg_v2(struct ir_insn *insn)
{
	struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(insn);
	bpf_ir_ptrset_free(&extra->adj);
	bpf_ir_ptrset_free(&extra->in);
	bpf_ir_ptrset_free(&extra->out);
	free_proto(extra);
	insn->user_data = NULL;
}

static enum val_type vtype(struct ir_value val)
{
	if (val.type == IR_VALUE_FLATTEN_DST) {
		if (val.data.vr_pos.allocated) {
			if (val.data.vr_pos.spilled) {
				// WARNING: cannot determine whether it's a stackoff
				return STACK;
			} else {
				return REG;
			}
		} else {
			return UNDEF;
		}
	} else if (val.type == IR_VALUE_CONSTANT ||
		   val.type == IR_VALUE_CONSTANT_RAWOFF ||
		   val.type == IR_VALUE_CONSTANT_RAWOFF_REV) {
		return CONST;
	} else {
		CRITICAL("No such value type for norm!");
	}
}

static enum val_type vtype_insn_norm(struct ir_insn *insn)
{
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	if (extra->pos.allocated) {
		if (extra->pos.spilled) {
			// WARNING: cannot determine whether it's a stackoff
			return STACK;
		} else {
			return REG;
		}
	} else {
		return UNDEF;
	}
}

static void remove_all_users(struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			bpf_ir_array_free(&insn->users);
		}
	}
	for (u8 i = 0; i < MAX_FUNC_ARG; ++i) {
		bpf_ir_array_free(&fun->function_arg[i]->users);
	}
	if (fun->sp) {
		bpf_ir_array_free(&fun->sp->users);
	}
	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		bpf_ir_array_free(&insn->users);
	}
}

// To flatten IR, we first need to change all the values to ir_pos
static void change_all_value_to_ir_pos(struct bpf_ir_env *env,
				       struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct array operands = bpf_ir_get_operands(env, insn);
			struct ir_value **pos2;
			array_for(pos2, operands)
			{
				struct ir_value *v = *pos2;
				if (v->type == IR_VALUE_INSN) {
					struct ir_insn *insn_d = v->data.insn_d;
					struct ir_insn *dst =
						insn_cg_v2(insn_d)->dst;
					struct ir_insn_cg_extra_v2 *extra =
						insn_cg_v2(dst);
					v->type = IR_VALUE_FLATTEN_DST;
					v->data.vr_pos = extra->vr_pos;
				}
			}
		}
	}
}

// Free CG resources, create a new extra data for flattening
static void cg_to_flatten(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_vr_pos pos;
			struct ir_insn_cg_extra_v2 *insn_extra =
				insn_cg_v2(insn);
			if (!insn_extra->dst) {
				pos.allocated = false;
			} else {
				struct ir_insn_cg_extra_v2 *dst_extra =
					insn_cg_v2(insn_extra->dst);
				pos = dst_extra->vr_pos;
			}
			insn_cg_v2(insn)->vr_pos = pos;
		}
	}

	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_cg_extra_v2 *extra = insn_cg_v2(insn);
			struct ir_vr_pos pos = extra->vr_pos;
			bpf_ir_free_insn_cg_v2(insn);
			SAFE_MALLOC(insn->user_data,
				    sizeof(struct ir_insn_norm_extra));
			insn_norm(insn)->pos = pos;
		}
	}

	for (u8 i = 0; i < BPF_REG_10; ++i) {
		struct ir_insn *insn = fun->cg_info.regs[i];
		bpf_ir_free_insn_cg_v2(insn);
	}
	bpf_ir_free_insn_cg_v2(fun->sp);
}

static void cgir_load_stack_to_reg_norm(struct bpf_ir_env *env,
					struct ir_insn *insn,
					struct ir_value *val,
					enum ir_vr_type vtype,
					struct ir_vr_pos reg)
{
	struct ir_insn *tmp = bpf_ir_create_assign_insn_norm(
		env, insn, reg, *val, INSERT_FRONT);
	tmp->vr_type = vtype;

	*val = bpf_ir_value_vrpos(reg);
}

/* Flatten IR */
static void flatten_ir(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Make sure no users
	remove_all_users(fun);
	change_all_value_to_ir_pos(env, fun);
	CHECK_ERR();
	cg_to_flatten(env, fun);
	CHECK_ERR();
}

/* Loading constant used in normalization */
static struct ir_insn *normalize_load_const(struct bpf_ir_env *env,
					    struct ir_insn *insn,
					    struct ir_value *val,
					    struct ir_vr_pos dst)
{
	struct ir_insn *new_insn = NULL;
	if (val->const_type == IR_ALU_32) {
		new_insn = bpf_ir_create_assign_insn_norm(env, insn, dst, *val,
							  INSERT_FRONT);
		new_insn->alu_op = IR_ALU_64;
	} else {
		new_insn = bpf_ir_create_loadimmextra_insn_norm(
			env, insn, dst, IR_LOADIMM_IMM64, val->data.constant_d,
			INSERT_FRONT);
		new_insn->vr_type = IR_VR_TYPE_64;
	}
	*val = bpf_ir_value_vrpos(dst);
	return new_insn;
}

static void normalize_assign(struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type tdst = vtype_insn_norm(insn);
	struct ir_vr_pos dst_pos = insn_norm(insn)->pos;
	// stack = reg
	// stack = const32
	// reg = const32
	// reg = const64
	// reg = stack
	// reg = reg
	if (tdst == STACK) {
		DBGASSERT(t0 != STACK);
		// Change to STORERAW
		insn->op = IR_INSN_STORERAW;

		insn->addr_val.value = bpf_ir_value_norm_stack_ptr();
		insn->addr_val.offset = dst_pos.spilled;
		insn->vr_type =
			IR_VR_TYPE_64; // TODO: Should be 64 before normalize
	} else {
		if (t0 == STACK) {
			// Change to LOADRAW
			insn->op = IR_INSN_LOADRAW;
			insn->addr_val.value = bpf_ir_value_norm_stack_ptr();
			insn->addr_val.offset = v0->data.vr_pos.spilled;
		}
		if (t0 == CONST && v0->const_type == IR_ALU_64) {
			// 64 imm load
			insn->op = IR_INSN_LOADIMM_EXTRA;
			insn->imm_extra_type = IR_LOADIMM_IMM64;
			insn->imm64 = v0->data.constant_d;
		}
	}
	if (tdst == REG && t0 == REG) {
		if (dst_pos.alloc_reg == v0->data.vr_pos.alloc_reg) {
			// The same, erase this instruction
			bpf_ir_erase_insn_norm(insn);
		}
	}
}

static void normalize_cond_jmp(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) : UNDEF;

	if (t0 == CONST) {
		// jmp const reg
		if (t1 == CONST) {
			if (insn->op == IR_INSN_JNE) {
				if (v0->data.constant_d !=
				    v1->data.constant_d) {
					// Jump
					insn->op = IR_INSN_JA;
					insn->value_num = 0;
					insn->bb1 =
						insn->bb2; // Jump to the next
					insn->bb2 = NULL;
				} else {
					// No jump
					bpf_ir_erase_insn_norm(insn);
				}
			} else {
				RAISE_ERROR(
					"conditional jmp requires at least one variable");
			}
			return;
		}
		if (insn->op == IR_INSN_JGT) {
			insn->op = IR_INSN_JLT;
		} else if (insn->op == IR_INSN_JEQ) {
		} else if (insn->op == IR_INSN_JNE) {
		} else if (insn->op == IR_INSN_JLT) {
			insn->op = IR_INSN_JGT;
		} else if (insn->op == IR_INSN_JGE) {
			insn->op = IR_INSN_JLE;
		} else if (insn->op == IR_INSN_JLE) {
			insn->op = IR_INSN_JGE;
		} else if (insn->op == IR_INSN_JSGE) {
			insn->op = IR_INSN_JSLE;
		} else if (insn->op == IR_INSN_JSLE) {
			insn->op = IR_INSN_JSGE;
		} else if (insn->op == IR_INSN_JSGT) {
			insn->op = IR_INSN_JSLT;
		} else if (insn->op == IR_INSN_JSLT) {
			insn->op = IR_INSN_JSGT;
		} else {
			RAISE_ERROR("unknown conditional jmp operation");
		}
		struct ir_value tmp = *v0;
		*v0 = *v1;
		*v1 = tmp;
	}
}

/* Normalize ALU */
static void normalize_alu(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) : UNDEF;
	enum val_type tdst = vtype_insn_norm(insn);
	DBGASSERT(tdst == REG);
	struct ir_vr_pos dst_pos = insn_norm(insn)->pos;
	if (t1 == REG) {
		if (dst_pos.alloc_reg == v1->data.vr_pos.alloc_reg) {
			if (bpf_ir_is_commutative_alu(insn)) {
				// Switch
				struct ir_value tmp = *v1;
				*v1 = *v0;
				*v0 = tmp;
				enum val_type tmp2 = t1;
				t1 = t0;
				t0 = tmp2;
			} else if (insn->op == IR_INSN_SUB) {
				// reg1 = sub XX reg1
				// ==>
				// reg1 = -reg1
				// reg1 = add reg1 XX
				bpf_ir_create_neg_insn_norm(env, insn, dst_pos,
							    IR_ALU_64, *v1,
							    INSERT_FRONT);
				insn->op = IR_INSN_ADD;
				struct ir_value tmp = *v1;
				*v1 = *v0;
				*v0 = tmp;
				enum val_type tmp2 = t1;
				t1 = t0;
				t0 = tmp2;
			} else {
				print_raw_ir_insn(env, insn);
				RAISE_ERROR(
					"non-commutative ALU op not supported yet");
			}
		}
	}
	if (t0 == CONST) {
		DBGASSERT(v0->const_type == IR_ALU_32);
	}
	if (t1 == CONST) {
		DBGASSERT(v1->const_type == IR_ALU_32);
	}
	// Binary ALU
	if (t0 == STACK && t1 == CONST) {
		// reg1 = add stack const
		// ==>
		// reg1 = stack
		// reg1 = add reg1 const
		struct ir_insn *new_insn = bpf_ir_create_assign_insn_norm(
			env, insn, dst_pos, *v0, INSERT_FRONT);
		new_insn->vr_type = IR_VR_TYPE_64;
		*v0 = bpf_ir_value_vrpos(dst_pos);
		normalize_assign(new_insn);

	} else if (t0 == STACK && t1 == REG) {
		// reg1 = add stack reg2
		// ==>
		// reg1 = stack
		// reg1 = add reg1 reg2
		struct ir_insn *new_insn = bpf_ir_create_assign_insn_norm(
			env, insn, dst_pos, *v0, INSERT_FRONT);
		new_insn->vr_type = IR_VR_TYPE_64;
		*v0 = bpf_ir_value_vrpos(dst_pos);
		normalize_assign(new_insn);
	} else if (t0 == REG && t1 == REG) {
		// reg1 = add reg2 reg3
		u8 reg1 = dst_pos.alloc_reg;
		u8 reg2 = v0->data.vr_pos.alloc_reg;
		if (reg1 != reg2) {
			// reg1 = add reg2 reg3
			// ==>
			// reg1 = reg2
			// reg1 = add reg1 reg3
			bpf_ir_create_assign_insn_norm(env, insn, dst_pos, *v0,
						       INSERT_FRONT);
			// DBGASSERT(dst_insn ==
			// 	  fun->cg_info.regs[reg1]); // Fixed reg?
			// TODO: Investigate here, why did I write this check?
			*v0 = bpf_ir_value_vrpos(dst_pos);
		}
	} else if (t0 == REG && t1 == CONST) {
		if (v0->data.vr_pos.alloc_reg != dst_pos.alloc_reg) {
			// reg1 = add reg2 const
			// ==>
			// reg1 = reg2
			// reg1 = add reg1 const
			bpf_ir_create_assign_insn_norm(env, insn, dst_pos, *v0,
						       INSERT_FRONT);
			*v0 = bpf_ir_value_vrpos(dst_pos);
		}
	} else if (t0 == CONST && t1 == CONST) {
		DBGASSERT(v1->const_type == IR_ALU_32);
		normalize_load_const(env, insn, v0, dst_pos);
	} else if (t0 == CONST && t1 == REG) {
		// reg1 = add const reg2
		// ==>
		// reg1 = const
		// reg1 = add reg1 reg2
		normalize_load_const(env, insn, v0, dst_pos);

	} else {
		CRITICAL_DUMP(env, "Error");
	}
}

static void normalize_getelemptr(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(*v1) : UNDEF;

	DBGASSERT(t1 == STACK);
	struct ir_vr_pos dstpos = insn_norm(insn)->pos;
	DBGASSERT(dstpos.allocated && dstpos.spilled == 0); // dst must be reg
	u8 dstreg = dstpos.alloc_reg;
	struct ir_vr_pos v1pos = v1->data.vr_pos;
	s32 spill_pos = v1pos.spilled;
	insn->op = IR_INSN_ADD;
	insn->alu_op = IR_ALU_64;
	if (t0 == CONST) {
		// reg = getelemptr const ptr
		// ==>
		// reg = r10 + (const + spill_pos)
		DBGASSERT(v0->const_type == IR_ALU_32);
		*v0 = bpf_ir_value_norm_stack_ptr();
		s64 tmp = v0->data.constant_d + spill_pos; // Assume no overflow
		*v1 = bpf_ir_value_const32(tmp);
		normalize_alu(env, insn);
	}
	if (t0 == REG) {
		u8 v0reg = v0->data.vr_pos.alloc_reg;
		*v1 = bpf_ir_value_const32(spill_pos);
		if (v0reg == dstreg) {
			// reg = getelemptr reg ptr
			// ==>
			// reg += r10
			// reg += spill_pos
			*v0 = bpf_ir_value_vrpos(dstpos);
			bpf_ir_create_bin_insn_norm(
				env, insn, dstpos, bpf_ir_value_vrpos(dstpos),
				bpf_ir_value_norm_stack_ptr(), IR_INSN_ADD,
				IR_ALU_64, INSERT_FRONT);
		} else {
			// reg1 = getelemptr reg2 ptr
			// ==>
			// reg1 = reg2
			// reg1 += r10
			// reg1 += spill_pos
			bpf_ir_create_assign_insn_norm(env, insn, dstpos, *v0,
						       INSERT_FRONT);
			bpf_ir_create_bin_insn_norm(
				env, insn, dstpos, bpf_ir_value_vrpos(dstpos),
				bpf_ir_value_norm_stack_ptr(), IR_INSN_ADD,
				IR_ALU_64, INSERT_FRONT);
			*v0 = bpf_ir_value_vrpos(dstpos);
		}
	}
}

static void normalize_store(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	struct ir_value *v1 = &insn->values[1];
	// store v0, v1
	// ==>
	// v0 = v1
	insn->op = IR_INSN_ASSIGN;
	insn_norm(insn)->pos = v0->data.vr_pos;
	*v0 = *v1;
	insn->value_num = 1;
	normalize_assign(insn);
}

static void normalize_load(struct bpf_ir_env *env, struct ir_insn *insn)
{
	// struct ir_value *v0 = &insn->values[0];
	// enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	// enum val_type tdst = vtype_insn_norm(insn);
	// reg1 = load reg2
	// ==>
	// reg1 = reg2
	insn->op = IR_INSN_ASSIGN;
	normalize_assign(insn);
}

static void normalize_stackoff(struct ir_insn *insn)
{
	// Could be storeraw or loadraw
	// Stack already shifted
	struct ir_value addrval = insn->addr_val.value;
	enum val_type addr_ty = vtype(addrval);
	// storeraw STACKOFF ?
	// ==>
	// storeraw r10 ?
	if (addr_ty == STACK) {
		insn->addr_val.offset += addrval.data.vr_pos.spilled;
		insn->addr_val.value = bpf_ir_value_norm_stack_ptr();
	}
}

static void normalize_neg(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type tdst = vtype_insn_norm(insn);
	DBGASSERT(tdst == REG);
	struct ir_vr_pos dst_pos = insn_norm(insn)->pos;
	// reg = neg reg ==> OK!
	if (t0 == REG && v0->data.vr_pos.alloc_reg != dst_pos.alloc_reg) {
		// reg1 = neg reg2
		// ==>
		// reg1 = reg2
		// reg1 = neg reg1
		bpf_ir_create_assign_insn_norm(env, insn, dst_pos, *v0,
					       INSERT_FRONT);
		*v0 = bpf_ir_value_vrpos(dst_pos);
	}
	if (t0 == CONST) {
		// reg = neg const
		RAISE_ERROR("Not supported");
	} else if (t0 == STACK) {
		// reg = neg stack
		// ==>
		// reg = stack
		// reg = neg reg
		cgir_load_stack_to_reg_norm(env, insn, v0, IR_VR_TYPE_64,
					    dst_pos);
	}
}

static void normalize_end(struct bpf_ir_env *env, struct ir_insn *insn)
{
	struct ir_value *v0 = &insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	enum val_type tdst = vtype_insn_norm(insn);
	DBGASSERT(tdst == REG);
	struct ir_vr_pos dst_pos = insn_norm(insn)->pos;
	// reg = end reg
	if (t0 == REG && v0->data.vr_pos.alloc_reg != dst_pos.alloc_reg) {
		// reg1 = end reg2
		// ==>
		// reg1 = reg2
		// reg1 = end reg1
		bpf_ir_create_assign_insn_norm(env, insn, dst_pos, *v0,
					       INSERT_FRONT);
		*v0 = bpf_ir_value_vrpos(dst_pos);
	}
	// reg = neg const ==> Not supported
	if (t0 == CONST) {
		RAISE_ERROR("Not supported");
	} else if (t0 == STACK) {
		// reg = end stack
		// ==>
		// reg = stack
		// reg = end reg
		cgir_load_stack_to_reg_norm(env, insn, v0, IR_VR_TYPE_64,
					    dst_pos);
	}
}

static void normalize_ret(struct bpf_ir_env *env, struct ir_insn *insn)
{
	if (insn->value_num == 0) {
		return;
	}
	struct ir_value *v0 = &insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(*v0) : UNDEF;
	// ret REG
	// ==>
	// R0 = REG
	// ret
	DBGASSERT(t0 == REG || t0 == CONST);
	struct ir_vr_pos pos = (struct ir_vr_pos){ .allocated = true,
						   .alloc_reg = BPF_REG_0,
						   .spilled = 0 };
	struct ir_insn *new_insn = bpf_ir_create_assign_insn_norm(
		env, insn, pos, *v0, INSERT_FRONT);
	new_insn->vr_type = IR_VR_TYPE_64;
	insn->value_num = 0;
}

static void normalize(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (insn->op == IR_INSN_ALLOC) {
				// OK
			} else if (insn->op == IR_INSN_ALLOCARRAY) {
				// OK
			} else if (insn->op == IR_INSN_GETELEMPTR) {
				normalize_getelemptr(env, insn);
			} else if (insn->op == IR_INSN_STORE) {
				normalize_store(env, insn);
			} else if (insn->op == IR_INSN_LOAD) {
				normalize_load(env, insn);
			} else if (insn->op == IR_INSN_LOADRAW) {
				normalize_stackoff(insn);
			} else if (insn->op == IR_INSN_LOADIMM_EXTRA) {
				// OK
			} else if (insn->op == IR_INSN_STORERAW) {
				normalize_stackoff(insn);
			} else if (insn->op == IR_INSN_NEG) {
				normalize_neg(env, insn);
			} else if (insn->op == IR_INSN_HTOBE ||
				   insn->op == IR_INSN_HTOLE) {
				normalize_end(env, insn);
			} else if (bpf_ir_is_bin_alu(insn)) {
				normalize_alu(env, insn);
			} else if (insn->op == IR_INSN_ASSIGN) {
				normalize_assign(insn);
			} else if (insn->op == IR_INSN_RET) {
				normalize_ret(env, insn);
			} else if (insn->op == IR_INSN_CALL) {
				// OK
			} else if (insn->op == IR_INSN_JA) {
				// OK
			} else if (bpf_ir_is_cond_jmp(insn)) {
				// jmp reg const/reg
				// or
				// jmp const reg
				// ==>
				// jmp(REV) reg const
				normalize_cond_jmp(env, insn);
			} else {
				RAISE_ERROR("No such instruction");
			}
			CHECK_ERR();
		}
	}
}

static void print_ir_prog_cg_flatten(struct bpf_ir_env *env,
				     struct ir_function *fun, char *msg)
{
	PRINT_LOG_DEBUG(env, "\x1B[32m----- CG: %s -----\x1B[0m\n", msg);
	print_ir_prog_advanced(env, fun, NULL, NULL, print_ir_flatten);
}

static struct pre_ir_insn translate_reg_to_reg(u8 dst, u8 src)
{
	// MOV dst src
	struct pre_ir_insn insn = { 0 };
	insn.opcode = BPF_MOV | BPF_X | BPF_ALU64;
	insn.dst_reg = dst;
	insn.src_reg = src;
	insn.imm = 0;
	return insn;
}

static struct pre_ir_insn translate_const_to_reg(u8 dst, s64 data,
						 enum ir_alu_op_type type)
{
	// MOV dst imm
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	if (type == IR_ALU_32) {
		insn.opcode = BPF_MOV | BPF_K | BPF_ALU;
	} else {
		// Default is imm64
		insn.opcode = BPF_MOV | BPF_K | BPF_ALU64;
	}
	insn.imm = data;
	return insn;
}

static int vr_type_to_size(enum ir_vr_type type)
{
	switch (type) {
	case IR_VR_TYPE_32:
		return BPF_W;
	case IR_VR_TYPE_16:
		return BPF_H;
	case IR_VR_TYPE_8:
		return BPF_B;
	case IR_VR_TYPE_64:
		return BPF_DW;
	default:
		CRITICAL("Error");
	}
}

static struct pre_ir_insn load_addr_to_reg(u8 dst, struct ir_address_value addr,
					   enum ir_vr_type type)
{
	// MOV dst src
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	insn.off = addr.offset;
	int size = vr_type_to_size(type);
	if (addr.value.type == IR_VALUE_FLATTEN_DST) {
		// Must be REG
		DBGASSERT(vtype(addr.value) == REG);
		// Load reg (addr) to reg
		insn.src_reg = addr.value.data.vr_pos.alloc_reg;
		insn.opcode = BPF_LDX | size | BPF_MEM;
	} else if (addr.value.type == IR_VALUE_CONSTANT) {
		// Must be U64
		insn.it = IMM64;
		insn.imm64 = addr.value.data.constant_d;
		insn.opcode = size;
		// Simplify the opcode to reduce compiler warning, the real opcode is as follows
		// (but BPF_MM and BPF_LD are all 0)
		// insn.opcode = BPF_IMM | size | BPF_LD;
	} else {
		CRITICAL("Error");
	}
	return insn;
}

static struct pre_ir_insn store_reg_to_reg_mem(u8 dst, u8 src, s16 offset,
					       enum ir_vr_type type)
{
	struct pre_ir_insn insn = { 0 };
	int size = vr_type_to_size(type);
	insn.src_reg = src;
	insn.off = offset;
	insn.opcode = BPF_STX | size | BPF_MEM;
	insn.dst_reg = dst;
	return insn;
}

static struct pre_ir_insn store_const_to_reg_mem(u8 dst, s64 val, s16 offset,
						 enum ir_vr_type type)
{
	struct pre_ir_insn insn = { 0 };
	int size = vr_type_to_size(type);
	insn.it = IMM;
	insn.imm = val;
	insn.off = offset;
	insn.opcode = BPF_ST | size | BPF_MEM;
	insn.dst_reg = dst;
	return insn;
}

static int end_code(enum ir_insn_type insn)
{
	if (insn == IR_INSN_HTOBE) {
		return BPF_TO_BE;
	} else if (insn == IR_INSN_HTOLE) {
		return BPF_TO_LE;
	} else {
		CRITICAL("Error");
	}
}

static int alu_code(enum ir_insn_type insn)
{
	switch (insn) {
	case IR_INSN_NEG:
		return BPF_NEG;
	case IR_INSN_ADD:
		return BPF_ADD;
	case IR_INSN_SUB:
		return BPF_SUB;
	case IR_INSN_MUL:
		return BPF_MUL;
	case IR_INSN_DIV:
		return BPF_DIV;
	case IR_INSN_OR:
		return BPF_OR;
	case IR_INSN_AND:
		return BPF_AND;
	case IR_INSN_MOD:
		return BPF_MOD;
	case IR_INSN_XOR:
		return BPF_XOR;
	case IR_INSN_LSH:
		return BPF_LSH;
	case IR_INSN_ARSH:
		return BPF_ARSH;
	case IR_INSN_RSH:
		return BPF_RSH;
	default:
		CRITICAL("Error");
	}
}

static int jmp_code(enum ir_insn_type insn)
{
	switch (insn) {
	case IR_INSN_JA:
		return BPF_JA;
	case IR_INSN_JEQ:
		return BPF_JEQ;
	case IR_INSN_JNE:
		return BPF_JNE;
	case IR_INSN_JLT:
		return BPF_JLT;
	case IR_INSN_JLE:
		return BPF_JLE;
	case IR_INSN_JGT:
		return BPF_JGT;
	case IR_INSN_JGE:
		return BPF_JGE;
	case IR_INSN_JSGE:
		return BPF_JSGE;
	case IR_INSN_JSLE:
		return BPF_JSLE;
	case IR_INSN_JSGT:
		return BPF_JSGT;
	case IR_INSN_JSLT:
		return BPF_JSLT;
	default:
		CRITICAL("Error");
	}
}

static struct pre_ir_insn alu_reg(u8 dst, u8 src, enum ir_alu_op_type type,
				  int opcode)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	insn.src_reg = src;
	int alu_class = type == IR_ALU_64 ? BPF_ALU64 : BPF_ALU;
	insn.opcode = opcode | BPF_X | alu_class;
	return insn;
}

static struct pre_ir_insn alu_neg(u8 dst, enum ir_alu_op_type type)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	int alu_class = type == IR_ALU_64 ? BPF_ALU64 : BPF_ALU;
	insn.opcode = BPF_NEG | BPF_K | alu_class;
	return insn;
}

static struct pre_ir_insn alu_end(u8 dst, s32 swap_width, int enty)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	insn.opcode = enty | BPF_END | BPF_ALU;
	insn.imm = swap_width;
	return insn;
}

static struct pre_ir_insn alu_imm(u8 dst, s64 src, enum ir_alu_op_type type,
				  int opcode)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	int alu_class = type == IR_ALU_64 ? BPF_ALU64 : BPF_ALU;
	insn.it = IMM;
	insn.imm = src;
	insn.opcode = opcode | BPF_K | alu_class;
	return insn;
}

static struct pre_ir_insn cond_jmp_reg(u8 dst, u8 src, enum ir_alu_op_type type,
				       int opcode)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	insn.src_reg = src;
	int alu_class = type == IR_ALU_64 ? BPF_JMP : BPF_JMP32;
	insn.opcode = opcode | alu_class | BPF_X;
	return insn;
}

static struct pre_ir_insn cond_jmp_imm(u8 dst, s64 src,
				       enum ir_alu_op_type type, int opcode)
{
	struct pre_ir_insn insn = { 0 };
	insn.dst_reg = dst;
	int alu_class = type == IR_ALU_64 ? BPF_JMP : BPF_JMP32;
	insn.it = IMM;
	insn.imm = src;
	insn.opcode = opcode | alu_class | BPF_K;
	return insn;
}

static u8 get_alloc_reg(struct ir_insn *insn)
{
	return insn_norm(insn)->pos.alloc_reg;
}

static void translate_loadraw(struct ir_insn *insn)
{
	enum val_type tdst = vtype_insn_norm(insn);
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	DBGASSERT(tdst == REG);
	extra->translated[0] = load_addr_to_reg(get_alloc_reg(insn),
						insn->addr_val, insn->vr_type);
}

static void translate_loadimm_extra(struct ir_insn *insn)
{
	enum val_type tdst = vtype_insn_norm(insn);
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	DBGASSERT(tdst == REG);
	extra->translated[0].opcode = BPF_IMM | BPF_LD | BPF_DW;
	DBGASSERT(insn->imm_extra_type <= 0x6);
	extra->translated[0].src_reg = insn->imm_extra_type;
	extra->translated[0].dst_reg = get_alloc_reg(insn);
	// 0 2 6 needs next
	extra->translated[0].it = IMM64;
	extra->translated[0].imm64 = insn->imm64;
}

static void translate_storeraw(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	// storeraw
	if (insn->addr_val.value.type == IR_VALUE_FLATTEN_DST) {
		// Store value in (address in the value)
		DBGASSERT(vtype(insn->addr_val.value) == REG);
		// Store value in the stack
		if (t0 == REG) {
			extra->translated[0] = store_reg_to_reg_mem(
				insn->addr_val.value.data.vr_pos.alloc_reg,
				v0.data.vr_pos.alloc_reg, insn->addr_val.offset,
				insn->vr_type);
		} else if (t0 == CONST) {
			extra->translated[0] = store_const_to_reg_mem(
				insn->addr_val.value.data.vr_pos.alloc_reg,
				v0.data.constant_d, insn->addr_val.offset,
				insn->vr_type);
		} else {
			CRITICAL("Error");
		}
	} else {
		CRITICAL("Error");
	}
}

static void translate_alu(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	struct ir_value v1 = insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(v1) : UNDEF;
	enum val_type tdst = vtype_insn_norm(insn);
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	DBGASSERT(tdst == REG);
	DBGASSERT(t0 == REG);
	DBGASSERT(get_alloc_reg(insn) == v0.data.vr_pos.alloc_reg);
	if (t1 == REG) {
		extra->translated[0] =
			alu_reg(get_alloc_reg(insn), v1.data.vr_pos.alloc_reg,
				insn->alu_op, alu_code(insn->op));
	} else if (t1 == CONST) {
		// Remove the instruction in some special cases
		if (insn->op == IR_INSN_ADD && v1.data.constant_d == 0) {
			extra->translated_num = 0;
			return;
		}
		extra->translated[0] = alu_imm(get_alloc_reg(insn),
					       v1.data.constant_d, insn->alu_op,
					       alu_code(insn->op));
	} else {
		CRITICAL("Error");
	}
}

static void translate_assign(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	enum val_type tdst = vtype_insn_norm(insn);
	struct ir_insn_norm_extra *extra = insn_norm(insn);

	// reg = const (alu)
	// reg = reg
	if (tdst == REG && t0 == CONST) {
		extra->translated[0] = translate_const_to_reg(
			get_alloc_reg(insn), v0.data.constant_d, insn->alu_op);
	} else if (tdst == REG && t0 == REG) {
		if (get_alloc_reg(insn) == v0.data.vr_pos.alloc_reg) {
			// Remove the instruction
			extra->translated_num = 0;
			return;
		}
		extra->translated[0] = translate_reg_to_reg(
			get_alloc_reg(insn), v0.data.vr_pos.alloc_reg);
	} else {
		CRITICAL("Error");
	}
}

static void translate_ret(struct ir_insn *insn)
{
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	extra->translated[0].opcode = BPF_EXIT | BPF_JMP;
}

static void translate_call(struct ir_insn *insn)
{
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	// Currently only support local helper functions
	extra->translated[0].opcode = BPF_CALL | BPF_JMP;
	extra->translated[0].it = IMM;
	extra->translated[0].imm = insn->fid;
}

static void translate_ja(struct ir_insn *insn)
{
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	extra->translated[0].opcode = BPF_JMP | BPF_JA;
}

static void translate_neg(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	enum val_type tdst = vtype_insn_norm(insn);
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	DBGASSERT(tdst == REG && t0 == REG);
	DBGASSERT(get_alloc_reg(insn) == v0.data.vr_pos.alloc_reg);
	extra->translated[0] = alu_neg(get_alloc_reg(insn), insn->alu_op);
}

static void translate_end(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	enum val_type tdst = vtype_insn_norm(insn);
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	DBGASSERT(tdst == REG);
	DBGASSERT(t0 == REG);
	DBGASSERT(get_alloc_reg(insn) == v0.data.vr_pos.alloc_reg);
	extra->translated[0] = alu_end(get_alloc_reg(insn), insn->swap_width,
				       end_code(insn->op));
}

static void translate_cond_jmp(struct ir_insn *insn)
{
	struct ir_value v0 = insn->values[0];
	struct ir_value v1 = insn->values[1];
	enum val_type t0 = insn->value_num >= 1 ? vtype(v0) : UNDEF;
	enum val_type t1 = insn->value_num >= 2 ? vtype(v1) : UNDEF;
	struct ir_insn_norm_extra *extra = insn_norm(insn);
	DBGASSERT(t0 == REG || t1 == REG);
	if (t0 == REG) {
		if (t1 == REG) {
			extra->translated[0] =
				cond_jmp_reg(v0.data.vr_pos.alloc_reg,
					     v1.data.vr_pos.alloc_reg,
					     insn->alu_op, jmp_code(insn->op));
		} else if (t1 == CONST) {
			if (v1.const_type == IR_ALU_64) {
				CRITICAL("TODO");
			}
			extra->translated[0] = cond_jmp_imm(
				v0.data.vr_pos.alloc_reg, v1.data.constant_d,
				insn->alu_op, jmp_code(insn->op));
		} else {
			CRITICAL("Error");
		}
	} else {
		DBGASSERT(t0 == CONST);
		DBGASSERT(t1 == REG);
		CRITICAL("TODO");
		// Probably we could switch?
		extra->translated[0] = cond_jmp_imm(v1.data.vr_pos.alloc_reg,
						    v0.data.constant_d,
						    insn->alu_op,
						    jmp_code(insn->op));
	}
}

static u32 bb_insn_cnt(struct ir_basic_block *bb)
{
	u32 cnt = 0;
	struct ir_insn *insn, *tmp;
	list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head, list_ptr) {
		if (insn->op == IR_INSN_ALLOC ||
		    insn->op == IR_INSN_ALLOCARRAY) {
			continue;
		} else {
			cnt++;
		}
	}
	return cnt;
}

static u32 bb_insn_critical_cnt(struct ir_basic_block *bb)
{
	u32 cnt = bb_insn_cnt(bb);
	while (bb->preds.num_elem <= 1) {
		if (bb->preds.num_elem == 0) {
			break;
		}
		struct ir_basic_block **tmp =
			bpf_ir_array_get_void(&bb->preds, 0);
		bb = *tmp;
		if (bb->flag & IR_BB_HAS_COUNTER) {
			break;
		}
		cnt += bb_insn_cnt(bb);
	}
	return cnt;
}

static void replace_builtin_const(struct bpf_ir_env *env,
				  struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			struct array operands = bpf_ir_get_operands(env, insn);
			struct ir_value **val;
			array_for(val, operands)
			{
				struct ir_value *v = *val;
				if (v->type == IR_VALUE_CONSTANT) {
					if (v->builtin_const ==
					    IR_BUILTIN_BB_INSN_CNT) {
						v->data.constant_d =
							bb_insn_cnt(bb);
					}
					if (v->builtin_const ==
					    IR_BUILTIN_BB_INSN_CRITICAL_CNT) {
						v->data.constant_d =
							bb_insn_critical_cnt(
								bb);
					}
				}
			}
			bpf_ir_array_free(&operands);
		}
	}
}

static void check_total_insn(struct bpf_ir_env *env, struct ir_function *fun)
{
	u32 cnt = 0;
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			struct ir_insn_norm_extra *extra = insn_norm(insn);
			cnt += extra->translated_num;
		}
	}
	if (cnt >= 1000000) {
		RAISE_ERROR("Too many instructions");
	}
}

static void translate(struct bpf_ir_env *env, struct ir_function *fun)
{
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			struct ir_insn_norm_extra *extra = insn_norm(insn);
			extra->translated_num = 1; // Default: 1 instruction
			if (insn->op == IR_INSN_ALLOC) {
				// Nothing to do
				extra->translated_num = 0;
			} else if (insn->op == IR_INSN_ALLOCARRAY) {
				// Nothing to do
				extra->translated_num = 0;
			} else if (insn->op == IR_INSN_STORE) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOAD) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_GETELEMPTR) {
				CRITICAL("Error");
			} else if (insn->op == IR_INSN_LOADRAW) {
				translate_loadraw(insn);
			} else if (insn->op == IR_INSN_LOADIMM_EXTRA) {
				translate_loadimm_extra(insn);
			} else if (insn->op == IR_INSN_STORERAW) {
				translate_storeraw(insn);
			} else if (insn->op == IR_INSN_NEG) {
				translate_neg(insn);
			} else if (insn->op == IR_INSN_HTOBE ||
				   insn->op == IR_INSN_HTOLE) {
				translate_end(insn);
			} else if (bpf_ir_is_bin_alu(insn)) {
				translate_alu(insn);
			} else if (insn->op == IR_INSN_ASSIGN) {
				translate_assign(insn);
			} else if (insn->op == IR_INSN_RET) {
				translate_ret(insn);
			} else if (insn->op == IR_INSN_CALL) {
				translate_call(insn);
			} else if (insn->op == IR_INSN_JA) {
				translate_ja(insn);
			} else if (bpf_ir_is_cond_jmp(insn)) {
				translate_cond_jmp(insn);
			} else {
				RAISE_ERROR("No such instruction");
			}
		}
	}
}

// Relocate BB
static void calc_pos(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Calculate the position of each instruction & BB
	size_t ipos = 0; // Instruction position
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_bb_cg_extra *bb_extra = bb->user_data;
		bb_extra->pos = ipos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_norm_extra *insn_extra = insn_norm(insn);
			for (u8 i = 0; i < insn_extra->translated_num; ++i) {
				struct pre_ir_insn *translated_insn =
					&insn_extra->translated[i];
				// Pos
				translated_insn->pos = ipos;
				if (translated_insn->it == IMM) {
					ipos += 1;
				} else {
					ipos += 2;
				}
			}
		}
	}
	env->insn_cnt = ipos;
}

static void relocate(struct bpf_ir_env *env, struct ir_function *fun)
{
	calc_pos(env, fun);
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_norm_extra *insn_extra = insn_norm(insn);
			if (insn->op == IR_INSN_JA) {
				DBGASSERT(insn_extra->translated_num == 1);
				size_t target = bpf_ir_bb_cg(insn->bb1)->pos;
				insn_extra->translated[0].off =
					target - insn_extra->translated[0].pos -
					1;
			}
			if (bpf_ir_is_cond_jmp(insn)) {
				DBGASSERT(insn_extra->translated_num == 1);
				size_t target = bpf_ir_bb_cg(insn->bb2)->pos;
				insn_extra->translated[0].off =
					target - insn_extra->translated[0].pos -
					1;
			}
		}
	}
}

static void synthesize(struct bpf_ir_env *env, struct ir_function *fun)
{
	// The last step, synthesizes the program
	SAFE_MALLOC(env->insns, env->insn_cnt * sizeof(struct bpf_insn));
	struct ir_basic_block **pos = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			struct ir_insn_norm_extra *extra = insn_norm(insn);
			for (u8 i = 0; i < extra->translated_num; ++i) {
				struct pre_ir_insn translated_insn =
					extra->translated[i];
				// PRINT_DBG("Writing to insn %zu\n",
				// 	  translated_insn.pos);
				struct bpf_insn *real_insn =
					&env->insns[translated_insn.pos];
				real_insn->code = translated_insn.opcode;
				real_insn->dst_reg = translated_insn.dst_reg;
				real_insn->src_reg = translated_insn.src_reg;
				real_insn->off = translated_insn.off;
				if (translated_insn.it == IMM) {
					real_insn->imm = translated_insn.imm;
				} else {
					// Wide instruction
					struct bpf_insn *real_insn2 =
						&env->insns[translated_insn.pos +
							    1];
					real_insn->imm = translated_insn.imm64 &
							 0xffffffff;
					real_insn2->imm =
						translated_insn.imm64 >> 32;
				}
			}
		}
	}
}

static void free_cg_final(struct ir_function *fun)
{
	// Free CG resources (after flattening)

	struct ir_basic_block **pos = NULL;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_bb_cg_extra *bb_cg = bb->user_data;
		free_proto(bb_cg);
		bb->user_data = NULL;

		struct ir_insn *insn = NULL;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			free_proto(insn->user_data);
			insn->user_data = NULL;
		}
	}
}

void bpf_ir_cg_norm_v2(struct bpf_ir_env *env, struct ir_function *fun)
{
	flatten_ir(env, fun);
	CHECK_ERR();

	print_ir_prog_cg_flatten(env, fun, "Flattening");

	normalize(env, fun);
	CHECK_ERR();
	print_ir_prog_cg_flatten(env, fun, "Normalization");

	replace_builtin_const(env, fun);
	CHECK_ERR();

	translate(env, fun);
	CHECK_ERR();

	check_total_insn(env, fun);
	CHECK_ERR();

	relocate(env, fun);
	CHECK_ERR();

	synthesize(env, fun);
	CHECK_ERR();

	// Free CG resources
	free_cg_final(fun);
}
