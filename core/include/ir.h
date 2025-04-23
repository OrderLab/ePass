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


#define MAX_FUNC_ARG 5

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


#endif