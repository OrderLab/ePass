/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_IR_H
#define _LINUX_IR_H

/*
Internal functions and definitions for BPF IR.
*/

#include <linux/bpf_ir.h>

#ifdef __KERNEL__

#include <linux/sort.h>
#define qsort(a, b, c, d) sort(a, b, c, d, NULL)

#endif

#define CHECK_ERR(x)      \
	if (env->err) {   \
		return x; \
	}

/* LLI Start */

void *malloc_proto(size_t size);

void free_proto(void *ptr);

int parse_int(const char *str, int *val);

u64 get_cur_time_ns(void);

#define SAFE_MALLOC(dst, size)              \
	{                                   \
		dst = malloc_proto(size);   \
		if (!dst) {                 \
			env->err = -ENOMEM; \
			return;             \
		}                           \
	}

#define SAFE_MALLOC_RET_NULL(dst, size)     \
	{                                   \
		dst = malloc_proto(size);   \
		if (!dst) {                 \
			env->err = -ENOMEM; \
			return NULL;        \
		}                           \
	}

/* LLI End */

enum imm_type { IMM, IMM64 };

/* Pre-IR instructions, similar to `bpf_insn` */
struct pre_ir_insn {
	u8 opcode;

	u8 dst_reg;
	u8 src_reg;
	s16 off;

	enum imm_type it;
	s32 imm;
	s64 imm64; // Immediate constant for 64-bit immediate

	size_t pos; // Original position
};

int bpf_ir_valid_alu_type(enum ir_alu_op_type type);

int bpf_ir_valid_vr_type(enum ir_vr_type type);

/**
    Pre-IR BB

    This includes many data structures needed to generate the IR.
 */
struct pre_ir_basic_block {
	// An ID used to debug
	size_t id;

	// Start position in the original insns
	size_t start_pos;

	// End position in the original insns
	size_t end_pos;

	// The number of instructions in this basic block (modified length)
	size_t len;

	struct pre_ir_insn *pre_insns;

	struct array preds;
	struct array succs;

	u8 visited;

	u8 sealed;
	u8 filled;
	struct ir_basic_block *ir_bb;
	struct ir_insn *incompletePhis[MAX_BPF_REG];
};

/**
    The BB value used in currentDef
 */
struct bb_val {
	struct pre_ir_basic_block *bb;
	struct ir_value val;
};

/**
    BB with the raw entrance position
 */
struct bb_entrance_info {
	size_t entrance;
	struct pre_ir_basic_block *bb;
};

/**
    Generated BB information
 */
struct bb_info {
	struct pre_ir_basic_block *entry;

	// Array of bb_entrance_info
	struct array all_bbs;
};

/**
    The environment data for transformation
 */
struct ssa_transform_env {
	// Array of bb_val (which is (BB, Value) pair)
	struct array currentDef[MAX_BPF_REG];
	struct bb_info info;

	// Stack Pointer
	struct ir_insn *sp;

	// Function argument
	struct ir_insn *function_arg[MAX_FUNC_ARG];
};

void bpf_ir_run_passes(struct bpf_ir_env *env, struct ir_function *fun,
		       const struct function_pass *passes, const size_t cnt);

#endif
