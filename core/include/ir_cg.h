#ifndef _IR_CG_H
#define _IR_CG_H

#include <linux/bpf_ir.h>

// Number of colors available (r0 - r9)
#define RA_COLORS 10

void bpf_ir_init_insn_cg(struct bpf_ir_env *env, struct ir_insn *insn);

void bpf_ir_init_insn_norm(struct bpf_ir_env *env, struct ir_insn *insn,
			   struct ir_vr_pos pos);

void bpf_ir_cg_norm_v2(struct bpf_ir_env *env, struct ir_function *fun);

void bpf_ir_init_insn_cg_v2(struct bpf_ir_env *env, struct ir_insn *insn);

void bpf_ir_free_insn_cg(struct ir_insn *insn);

// Extra information needed for code gen
struct ir_bb_cg_extra {
	// Position of the first instruction
	size_t pos;
};

/* Instruction data used after RA (e.g. normalization) */
struct ir_insn_norm_extra {
	struct ir_vr_pos pos;

	// Translated pre_ir_insn
	struct pre_ir_insn translated[2];

	// Translated number
	u8 translated_num;
};

struct ir_insn_cg_extra {
	// Destination (Not in SSA form anymore)
	struct ir_value dst;

	// Liveness analysis
	// Array of struct ir_insn*
	struct array in;
	struct array out;
	struct array gen;
	struct array kill;

	// Adj list in interference graph
	// Array of struct ir_insn*
	struct array adj;

	// Whether the VR is allocated with a real register
	// If it's a pre-colored register, it's also 1
	bool allocated;

	// When allocating register, whether dst will be spilled
	// 0: Not spilled
	// -8: Spilled on SP-8
	// etc.
	s32 spilled;

	// The size of the spilled register
	u32 spilled_size;

	// Valid if spilled == 0 && allocated == 1
	// Valid number: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
	u8 alloc_reg;

	struct ir_vr_pos vr_pos;

	// Whether this instruction is a non-VR instruction, like a pre-colored register
	bool nonvr;
};

struct ir_insn_cg_extra_v2 {
	struct ir_insn *dst;

	// Liveness analysis
	struct ptrset in;
	struct ptrset out;

	// Adj list in interference graph
	struct ptrset adj;

	u32 lambda; // used in MCS
	u32 w; // number of maximalCl that has this vertex. used in pre-spill

	// Whether the vr_pos is finalized (pre-colored)
	// If not finalized, vr_pos will be cleaned in each iteration
	// of RA
	bool finalized;

	struct ir_vr_pos vr_pos;

	// Whether this instruction is a non-VR instruction, like a pre-colored register
	bool nonvr;
};

enum val_type {
	UNDEF,
	REG,
	CONST,
	STACK,
	STACKOFF,
};

#define insn_cg(insn) ((struct ir_insn_cg_extra *)(insn)->user_data)

#define insn_cg_v2(insn) ((struct ir_insn_cg_extra_v2 *)(insn)->user_data)

/* Dst of a instruction

Note. This could be only applied to an instruction with return value.
*/
#define insn_dst(insn) insn_cg(insn)->dst.data.insn_d

#define insn_dst_v2(insn) insn_cg_v2(insn)->dst

#define insn_norm(insn) ((struct ir_insn_norm_extra *)(insn)->user_data)

void bpf_ir_cg_norm(struct bpf_ir_env *env, struct ir_function *fun);

void bpf_ir_cg_prog_check(struct bpf_ir_env *env, struct ir_function *fun);

#endif
