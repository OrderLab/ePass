#ifndef __BPF_IR_CODE_GEN_H__
#define __BPF_IR_CODE_GEN_H__

#include <stdio.h>
#include "bpf_ir.h"
#include "ir_fun.h"

int code_gen(struct ir_function *fun);

// Extra information needed for code gen
struct ir_bb_cg_extra {
	// Position of the first instruction
	size_t pos;
};

struct ir_insn_cg_extra {
	// Destination (Not in SSA form anymore)
	struct ir_insn *dst;

	// Liveness analysis
	struct array in;
	struct array out;
	struct array gen;
	struct array kill;

	// Adj list in interference graph
	// Array of struct ir_insn*
	struct array adj;

	// Translated pre_ir_insn
	struct pre_ir_insn translated[2];

	// Translated number
	__u8 translated_num;

	// Whether the VR is allocated with a real register
	// If it's a pre-colored register, it's also 1
	__u8 allocated;

	// When allocating register, whether dst will be spilled
	// 0: Not spilled
	// 1: Spilled on stack position 1
	// etc.
	size_t spilled;

	// Valid if spilled == 0 && allocated == 1
	// Valid number: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
	__u8 alloc_reg;
};

enum val_type {
	UNDEF,
	REG,
	CONST,
	STACK,
};

struct ir_insn_cg_extra *insn_cg(struct ir_insn *insn);

struct ir_insn_cg_extra *init_insn_cg(struct ir_insn *insn);

struct ir_insn *dst(struct ir_insn *insn);

void to_cssa(struct ir_function *fun);

void remove_phi(struct ir_function *fun);

void print_ir_prog_cg(struct ir_function *fun);

void liveness_analysis(struct ir_function *fun);

void conflict_analysis(struct ir_function *fun);

void print_interference_graph(struct ir_function *fun);

void graph_coloring(struct ir_function *fun);

void explicit_reg(struct ir_function *fun);

void coaleasing(struct ir_function *fun);

enum val_type vtype(struct ir_value val);

int check_need_spill(struct ir_function *fun);

void translate(struct ir_function *fun);

void spill_callee(struct ir_function *fun);

enum val_type vtype_insn(struct ir_insn *insn);

void calc_callee_num(struct ir_function *fun);

void calc_stack_size(struct ir_function *fun);

void add_stack_offset_pre_cg(struct ir_function *fun);

// Add stack offset to all stack access
void add_stack_offset(struct ir_function *fun, __s16 offset);

void normalize(struct ir_function *fun);

void relocate(struct ir_function *fun);

enum ir_vr_type alu_to_vr_type(enum ir_alu_type ty);

#endif
