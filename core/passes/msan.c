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
			PRINT_LOG_DEBUG(
				env, "Found a stack pointer store at off %d\n",
				insn->addr_val.offset);
			u32 x = -insn->addr_val.offset;
			u32 b1 = x / 8 + 1;
			u32 b2 = b1 + 1;
			u32 off = 7 - (x % 8);
			struct ir_insn *b1c = bpf_ir_create_loadraw_insn(
				env, insn, IR_VR_TYPE_8,
				bpf_ir_addr_val(bpf_ir_value_stack_ptr(fun),
						-b1),
				INSERT_BACK);
			struct ir_insn *b2c = bpf_ir_create_loadraw_insn(
				env, b1c, IR_VR_TYPE_8,
				bpf_ir_addr_val(bpf_ir_value_stack_ptr(fun),
						-b2),
				INSERT_BACK);
			struct ir_insn *comp1 = bpf_ir_create_bin_insn(
				env, b2c, bpf_ir_value_insn(b1c),
				bpf_ir_value_const32(8), IR_INSN_LSH, IR_ALU_64,
				INSERT_BACK);
			struct ir_insn *comp2 = bpf_ir_create_bin_insn(
				env, comp1, bpf_ir_value_insn(comp1),
				bpf_ir_value_insn(b2c), IR_INSN_ADD, IR_ALU_64,
				INSERT_BACK);
			struct ir_insn *comp3 = bpf_ir_create_bin_insn(
				env, comp2, bpf_ir_value_insn(comp2),
				bpf_ir_value_const32(off), IR_INSN_RSH,
				IR_ALU_64, INSERT_BACK);
			struct ir_insn *res1 = bpf_ir_create_bin_insn(
				env, comp3, bpf_ir_value_insn(comp3),
				bpf_ir_value_const32(
					(1 << vr_type_to_size(insn->vr_type)) -
					1),
				IR_INSN_OR, IR_ALU_64, INSERT_BACK);
			struct ir_insn *res2 = bpf_ir_create_bin_insn(
				env, res1, bpf_ir_value_insn(res1),
				bpf_ir_value_const32(off), IR_INSN_LSH,
				IR_ALU_64, INSERT_BACK);
			bpf_ir_create_storeraw_insn(
				env, res2, IR_VR_TYPE_16,
				bpf_ir_addr_val(bpf_ir_value_stack_ptr(fun),
						-b2),
				bpf_ir_value_insn(res2), INSERT_BACK);
		}
	}
	array_for(pos2, loadraw_insns)
	{
		struct ir_insn *insn = *pos2;
		if (insn->addr_val.value.type == IR_VALUE_INSN &&
		    insn->addr_val.value.data.insn_d == fun->sp) {
			PRINT_LOG_DEBUG(
				env, "Found a stack pointer load at off %d\n",
				insn->addr_val.offset);
			u32 x = -insn->addr_val.offset;
			u32 b1 = x / 8 + 1;
			u32 b2 = b1 + 1;
			u32 off = 7 - (x % 8);
			struct ir_insn *b1c = bpf_ir_create_loadraw_insn(
				env, insn, IR_VR_TYPE_8,
				bpf_ir_addr_val(bpf_ir_value_stack_ptr(fun),
						-b1),
				INSERT_FRONT);
			struct ir_insn *b2c = bpf_ir_create_loadraw_insn(
				env, b1c, IR_VR_TYPE_8,
				bpf_ir_addr_val(bpf_ir_value_stack_ptr(fun),
						-b2),
				INSERT_BACK);
			struct ir_insn *comp1 = bpf_ir_create_bin_insn(
				env, b2c, bpf_ir_value_insn(b1c),
				bpf_ir_value_const32(8), IR_INSN_LSH, IR_ALU_64,
				INSERT_BACK);
			struct ir_insn *comp2 = bpf_ir_create_bin_insn(
				env, comp1, bpf_ir_value_insn(comp1),
				bpf_ir_value_insn(b2c), IR_INSN_ADD, IR_ALU_64,
				INSERT_BACK);
			struct ir_insn *comp3 = bpf_ir_create_bin_insn(
				env, comp2, bpf_ir_value_insn(comp2),
				bpf_ir_value_const32(off), IR_INSN_RSH,
				IR_ALU_64, INSERT_BACK);
			u32 mask = (1 << vr_type_to_size(insn->vr_type)) - 1;
			struct ir_insn *res1 = bpf_ir_create_bin_insn(
				env, comp3, bpf_ir_value_insn(comp3),
				bpf_ir_value_const32(mask), IR_INSN_AND,
				IR_ALU_64, INSERT_BACK);

			// struct ir_insn *res2 = bpf_ir_create_bin_insn(
			// 	env, res1, bpf_ir_value_insn(res1),
			// 	bpf_ir_value_const32(off), IR_INSN_LSH,
			// 	IR_ALU_64, INSERT_BACK);
			// bpf_ir_create_storeraw_insn(
			// 	env, res2, IR_VR_TYPE_16,
			// 	bpf_ir_addr_val(bpf_ir_value_stack_ptr(fun),
			// 			-b2),
			// 	bpf_ir_value_insn(res2), INSERT_BACK);
		}
	}

	bpf_ir_array_free(&storeraw_insns);
	bpf_ir_array_free(&loadraw_insns);
}

const struct builtin_pass_cfg bpf_ir_kern_msan =
	DEF_BUILTIN_PASS_CFG("msan", NULL, NULL);
