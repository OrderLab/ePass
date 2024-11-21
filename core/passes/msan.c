// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

static u8 vr_type_to_size(enum ir_vr_type type)
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

static void modify_loadraw(struct bpf_ir_env *env, struct ir_function *fun,
			   struct ir_insn *arr, struct ir_insn *insn)
{
	// Non-sp memory access
	// loadraw size addr(sp-32)
	// ==>
	// x = r10 - addr
	struct ir_basic_block *bb = insn->parent_bb;

	struct ir_value v = bpf_ir_value_stack_ptr(fun);
	v.raw_stack = true;
	struct ir_insn *s1 =
		bpf_ir_create_bin_insn(env, insn, v, insn->addr_val.value,
				       IR_INSN_SUB, IR_ALU_64, INSERT_FRONT);
	struct ir_insn *b1 = bpf_ir_create_bin_insn(
		env, s1, bpf_ir_value_insn(s1), bpf_ir_value_const32(8),
		IR_INSN_DIV, IR_ALU_64, INSERT_BACK);
	struct ir_insn *b2 = bpf_ir_create_bin_insn(
		env, b1, bpf_ir_value_insn(b1), bpf_ir_value_const32(1),
		IR_INSN_SUB, IR_ALU_64, INSERT_BACK);
	struct ir_insn *s3 = bpf_ir_create_bin_insn(
		env, b2, bpf_ir_value_insn(s1), bpf_ir_value_const32(8),
		IR_INSN_MOD, IR_ALU_64, INSERT_BACK);

	struct ir_insn *b1ptr = bpf_ir_create_getelemptr_insn(
		env, s3, arr, bpf_ir_value_insn(b1), INSERT_BACK);
	struct ir_insn *b1c = bpf_ir_create_loadraw_insn(
		env, b1ptr, IR_VR_TYPE_8,
		bpf_ir_addr_val(bpf_ir_value_insn(b1ptr), 0), INSERT_BACK);
	struct ir_insn *b2ptr = bpf_ir_create_getelemptr_insn(
		env, b1c, arr, bpf_ir_value_insn(b2), INSERT_BACK);
	struct ir_insn *b2c = bpf_ir_create_loadraw_insn(
		env, b2ptr, IR_VR_TYPE_8,
		bpf_ir_addr_val(bpf_ir_value_insn(b2ptr), 0), INSERT_BACK);

	// Memory layout: ... sp-16 b1 b2 sp-32 ...
	struct ir_insn *comp1 = bpf_ir_create_bin_insn(
		env, b2c, bpf_ir_value_insn(b1c), bpf_ir_value_const32(8),
		IR_INSN_LSH, IR_ALU_64, INSERT_BACK);
	struct ir_insn *comp2 = bpf_ir_create_bin_insn(
		env, comp1, bpf_ir_value_insn(comp1), bpf_ir_value_insn(b2c),
		IR_INSN_ADD, IR_ALU_64, INSERT_BACK);
	int masking_val = (1 << vr_type_to_size(insn->vr_type)) - 1;
	// off = pos%8 + 9 - size
	struct ir_insn *off = bpf_ir_create_bin_insn(
		env, comp2, bpf_ir_value_insn(s3),
		bpf_ir_value_const32(9 - vr_type_to_size(insn->vr_type)),
		IR_INSN_ADD, IR_ALU_64, INSERT_BACK);
	struct ir_insn *comp3 = bpf_ir_create_bin_insn(
		env, off, bpf_ir_value_insn(comp2), bpf_ir_value_insn(off),
		IR_INSN_RSH, IR_ALU_64, INSERT_BACK);
	// res = comp3 & masking
	struct ir_insn *res1 =
		bpf_ir_create_bin_insn(env, comp3, bpf_ir_value_insn(comp3),
				       bpf_ir_value_const32(masking_val),
				       IR_INSN_AND, IR_ALU_64, INSERT_BACK);

	struct ir_basic_block *new_bb =
		bpf_ir_split_bb(env, fun, res1, INSERT_BACK);
	struct ir_basic_block *err_bb = bpf_ir_create_bb(env, fun);
	bpf_ir_create_throw_insn_bb(env, err_bb, INSERT_BACK);
	bpf_ir_create_jbin_insn(env, res1, bpf_ir_value_insn(res1),
				bpf_ir_value_const32(masking_val), new_bb,
				err_bb, IR_INSN_JNE, IR_ALU_64, INSERT_BACK);
	// Manually connect BBs
	bpf_ir_connect_bb(env, bb, err_bb);
}

static void modify_storeraw(struct bpf_ir_env *env, struct ir_insn *arr,
			    struct ir_insn *insn)
{
	PRINT_LOG_DEBUG(env, "Found a stack pointer store at off %d\n",
			insn->addr_val.offset);
	struct ir_value s1 =
		bpf_ir_value_const32_rawoff(-insn->addr_val.offset);
	s1.type = IR_VALUE_CONSTANT_RAWOFF_REV;

	struct ir_insn *b1 =
		bpf_ir_create_bin_insn(env, insn, s1, bpf_ir_value_const32(8),
				       IR_INSN_DIV, IR_ALU_64, INSERT_BACK);
	struct ir_insn *b2 = bpf_ir_create_bin_insn(
		env, b1, bpf_ir_value_insn(b1), bpf_ir_value_const32(1),
		IR_INSN_SUB, IR_ALU_64, INSERT_BACK);
	struct ir_insn *s3 =
		bpf_ir_create_bin_insn(env, b2, s1, bpf_ir_value_const32(8),
				       IR_INSN_MOD, IR_ALU_64, INSERT_BACK);

	struct ir_insn *b1ptr = bpf_ir_create_getelemptr_insn(
		env, s3, arr, bpf_ir_value_insn(b1), INSERT_BACK);
	struct ir_insn *b1c = bpf_ir_create_loadraw_insn(
		env, b1ptr, IR_VR_TYPE_8,
		bpf_ir_addr_val(bpf_ir_value_insn(b1ptr), 0), INSERT_BACK);
	struct ir_insn *b2ptr = bpf_ir_create_getelemptr_insn(
		env, b1c, arr, bpf_ir_value_insn(b2), INSERT_BACK);
	struct ir_insn *b2c = bpf_ir_create_loadraw_insn(
		env, b2ptr, IR_VR_TYPE_8,
		bpf_ir_addr_val(bpf_ir_value_insn(b2ptr), 0), INSERT_BACK);

	// Memory layout: ... sp-16 b1 b2 sp-32 ...
	struct ir_insn *comp1 = bpf_ir_create_bin_insn(
		env, b2c, bpf_ir_value_insn(b1c), bpf_ir_value_const32(8),
		IR_INSN_LSH, IR_ALU_64, INSERT_BACK);
	struct ir_insn *comp2 = bpf_ir_create_bin_insn(
		env, comp1, bpf_ir_value_insn(comp1), bpf_ir_value_insn(b2c),
		IR_INSN_ADD, IR_ALU_64, INSERT_BACK);
	int masking_val = (1 << vr_type_to_size(insn->vr_type)) - 1;
	// off = pos%8 + 9 - size
	struct ir_insn *off = bpf_ir_create_bin_insn(
		env, comp2, bpf_ir_value_insn(s3),
		bpf_ir_value_const32(9 - vr_type_to_size(insn->vr_type)),
		IR_INSN_ADD, IR_ALU_64, INSERT_BACK);
	struct ir_insn *comp3 = bpf_ir_create_bin_insn(
		env, off, bpf_ir_value_const32(masking_val),
		bpf_ir_value_insn(off), IR_INSN_LSH, IR_ALU_64, INSERT_BACK);
	// res = comp3 | comp2
	struct ir_insn *res1 = bpf_ir_create_bin_insn(
		env, comp3, bpf_ir_value_insn(comp3), bpf_ir_value_insn(comp2),
		IR_INSN_OR, IR_ALU_64, INSERT_BACK);
	bpf_ir_create_storeraw_insn(env, res1, IR_VR_TYPE_16,
				    bpf_ir_addr_val(bpf_ir_value_insn(b2ptr),
						    0),
				    bpf_ir_value_insn(res1), INSERT_BACK);
}

void msan(struct bpf_ir_env *env, struct ir_function *fun, void *param)
{
	// Add the 64B mapping space
	struct ir_insn *arr = bpf_ir_create_allocarray_insn_bb(
		env, fun->entry, IR_VR_TYPE_64, 8, INSERT_FRONT_AFTER_PHI);
	for (int i = 0; i < 8; ++i) {
		bpf_ir_create_storeraw_insn(
			env, arr, IR_VR_TYPE_64,
			bpf_ir_addr_val(bpf_ir_value_insn(arr), i * 8),
			bpf_ir_value_const32(0), INSERT_BACK);
	}
	struct array storeraw_insns;
	struct array loadraw_insns;
	INIT_ARRAY(&storeraw_insns, struct ir_insn *);
	INIT_ARRAY(&loadraw_insns, struct ir_insn *);
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn;
		list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
			if (insn->op == IR_INSN_STORERAW) {
				bpf_ir_array_push(env, &storeraw_insns, &insn);
			}
			if (insn->op == IR_INSN_LOADRAW) {
				bpf_ir_array_push(env, &loadraw_insns, &insn);
			}
		}
	}

	struct ir_insn **pos2;
	array_for(pos2, storeraw_insns)
	{
		struct ir_insn *insn = *pos2;
		if (insn->addr_val.value.type == IR_VALUE_INSN &&
		    insn->addr_val.value.data.insn_d == fun->sp) {
			modify_storeraw(env, arr, insn);
		}
	}

	array_for(pos2, loadraw_insns)
	{
		struct ir_insn *insn = *pos2;
		// struct ir_basic_block *bb = insn->parent_bb;
		// if (bpf_ir_get_last_insn(bb) == insn) {
		// 	PRINT_LOG_WARNING(env, "Last insn is a loadraw insn\n");
		// 	continue;
		// }
		if (insn->addr_val.value.type == IR_VALUE_INSN &&
		    insn->addr_val.value.data.insn_d == fun->sp) {
			// Sp memory access
		} else if (insn->addr_val.value.type == IR_VALUE_INSN) {
			modify_loadraw(env, fun, arr, insn);
		}
	}

	bpf_ir_array_free(&storeraw_insns);
	bpf_ir_array_free(&loadraw_insns);
}

const struct builtin_pass_cfg bpf_ir_kern_msan =
	DEF_BUILTIN_PASS_CFG("msan", NULL, NULL);
