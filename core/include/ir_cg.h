#ifndef _IR_CG_H
#define _IR_CG_H

#include <linux/bpf_ir.h>

// Number of colors available (r0 - r9)
#define RA_COLORS 10

u32 bpf_ir_sizeof_vr_type(enum ir_vr_type type);

void bpf_ir_replace_all_usage_cg(struct bpf_ir_env *env, struct ir_insn *insn,
				 struct ir_value rep);

/* Erase an instruction during CG. Cannot erase if gen kill sets are used */
void bpf_ir_erase_insn_cg(struct bpf_ir_env *env, struct ir_function *fun,
			  struct ir_insn *insn);

void bpf_ir_erase_insn_norm(struct ir_insn *insn);

void bpf_ir_init_insn_cg(struct bpf_ir_env *env, struct ir_insn *insn);

void bpf_ir_init_insn_norm(struct bpf_ir_env *env, struct ir_insn *insn,
			   struct ir_vr_pos pos);

void bpf_ir_cg_norm_v2(struct bpf_ir_env *env, struct ir_function *fun);

void bpf_ir_init_insn_cg_v2(struct bpf_ir_env *env, struct ir_insn *insn);

void bpf_ir_free_insn_cg(struct ir_insn *insn);

struct ir_bb_cg_extra *bpf_ir_bb_cg(struct ir_basic_block *bb);

void print_ir_dst(struct bpf_ir_env *env, struct ir_insn *insn);

void print_ir_alloc(struct bpf_ir_env *env, struct ir_insn *insn);

void print_ir_flatten(struct bpf_ir_env *env, struct ir_insn *insn);

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

void bpf_ir_optimize_ir(struct bpf_ir_env *env, struct ir_function *fun,
			void *data);

void bpf_ir_cg_change_fun_arg(struct bpf_ir_env *env, struct ir_function *fun,
			      void *param);

void bpf_ir_cg_change_call_pre_cg(struct bpf_ir_env *env,
				  struct ir_function *fun, void *param);

void bpf_ir_cg_add_stack_offset_pre_cg(struct bpf_ir_env *env,
				       struct ir_function *fun, void *param);

void bpr_ir_cg_to_cssa(struct bpf_ir_env *env, struct ir_function *fun,
		       void *param);

/* Instruction Constructors */

struct ir_insn *bpf_ir_create_alloc_insn_cg_v2(struct bpf_ir_env *env,
					       struct ir_insn *pos_insn,
					       enum ir_vr_type type,
					       enum insert_position pos);

struct ir_insn *bpf_ir_create_alloc_insn_bb_cg_v2(struct bpf_ir_env *env,
						  struct ir_basic_block *pos_bb,
						  enum ir_vr_type type,
						  enum insert_position pos);

struct ir_insn *bpf_ir_create_loadimmextra_insn_cg(
	struct bpf_ir_env *env, struct ir_insn *pos_insn,
	enum ir_loadimm_extra_type load_ty, s64 imm, enum insert_position pos);

struct ir_insn *bpf_ir_create_loadimmextra_insn_bb_cg(
	struct bpf_ir_env *env, struct ir_basic_block *pos_bb,
	enum ir_loadimm_extra_type load_ty, s64 imm, enum insert_position pos);

struct ir_insn *bpf_ir_create_loadimmextra_insn_norm(
	struct bpf_ir_env *env, struct ir_insn *pos_insn,
	struct ir_vr_pos dstpos, enum ir_loadimm_extra_type load_ty, s64 imm,
	enum insert_position pos);

struct ir_insn *bpf_ir_create_loadimmextra_insn_bb_norm(
	struct bpf_ir_env *env, struct ir_basic_block *pos_bb,
	struct ir_vr_pos dstpos, enum ir_loadimm_extra_type load_ty, s64 imm,
	enum insert_position pos);

struct ir_insn *bpf_ir_create_getelemptr_insn_cg(struct bpf_ir_env *env,
						 struct ir_insn *pos_insn,
						 struct ir_insn *alloca_insn,
						 struct ir_value offset,
						 enum insert_position pos);

struct ir_insn *bpf_ir_create_getelemptr_insn_bb_cg(
	struct bpf_ir_env *env, struct ir_basic_block *pos_bb,
	struct ir_insn *alloca_insn, struct ir_value offset,
	enum insert_position pos);

struct ir_insn *bpf_ir_create_neg_insn_cg(struct bpf_ir_env *env,
					  struct ir_insn *pos_insn,
					  enum ir_alu_op_type alu_type,
					  struct ir_value val,
					  enum insert_position pos);

struct ir_insn *bpf_ir_create_neg_insn_bb_cg(struct bpf_ir_env *env,
					     struct ir_basic_block *pos_bb,
					     enum ir_alu_op_type alu_type,
					     struct ir_value val,
					     enum insert_position pos);

struct ir_insn *bpf_ir_create_neg_insn_norm(struct bpf_ir_env *env,
					    struct ir_insn *pos_insn,
					    struct ir_vr_pos dstpos,
					    enum ir_alu_op_type alu_type,
					    struct ir_value val,
					    enum insert_position pos);

struct ir_insn *bpf_ir_create_neg_insn_bb_norm(struct bpf_ir_env *env,
					       struct ir_basic_block *pos_bb,
					       struct ir_vr_pos dstpos,
					       enum ir_alu_op_type alu_type,
					       struct ir_value val,
					       enum insert_position pos);

struct ir_insn *bpf_ir_create_end_insn_cg(struct bpf_ir_env *env,
					  struct ir_insn *pos_insn,
					  enum ir_insn_type ty, u32 swap_width,
					  struct ir_value val,
					  enum insert_position pos);

struct ir_insn *bpf_ir_create_end_insn_bb_cg(struct bpf_ir_env *env,
					     struct ir_basic_block *pos_bb,
					     enum ir_insn_type ty,
					     u32 swap_width,
					     struct ir_value val,
					     enum insert_position pos);

struct ir_insn *bpf_ir_create_store_insn_cg_v2(struct bpf_ir_env *env,
					       struct ir_insn *pos_insn,
					       struct ir_insn *insn,
					       struct ir_value val,
					       enum insert_position pos);

struct ir_insn *bpf_ir_create_store_insn_bb_cg_v2(struct bpf_ir_env *env,
						  struct ir_basic_block *pos_bb,
						  struct ir_insn *insn,
						  struct ir_value val,
						  enum insert_position pos);

struct ir_insn *bpf_ir_create_load_insn_cg_v2(struct bpf_ir_env *env,
					      struct ir_insn *pos_insn,
					      struct ir_value val,
					      enum insert_position pos);

struct ir_insn *bpf_ir_create_load_insn_bb_cg_v2(struct bpf_ir_env *env,
						 struct ir_basic_block *pos_bb,
						 struct ir_value val,
						 enum insert_position pos);

struct ir_insn *
bpf_ir_create_bin_insn_cg(struct bpf_ir_env *env, struct ir_insn *pos_insn,
			  struct ir_value val1, struct ir_value val2,
			  enum ir_insn_type ty, enum ir_alu_op_type alu_type,
			  enum insert_position pos);

struct ir_insn *bpf_ir_create_bin_insn_bb_cg(
	struct bpf_ir_env *env, struct ir_basic_block *pos_bb,
	struct ir_value val1, struct ir_value val2, enum ir_insn_type ty,
	enum ir_alu_op_type alu_type, enum insert_position pos);

struct ir_insn *
bpf_ir_create_bin_insn_norm(struct bpf_ir_env *env, struct ir_insn *pos_insn,
			    struct ir_vr_pos dstpos, struct ir_value val1,
			    struct ir_value val2, enum ir_insn_type ty,
			    enum ir_alu_op_type alu_type,
			    enum insert_position pos);

struct ir_insn *bpf_ir_create_bin_insn_bb_norm(
	struct bpf_ir_env *env, struct ir_basic_block *pos_bb,
	struct ir_vr_pos dstpos, struct ir_value val1, struct ir_value val2,
	enum ir_insn_type ty, enum ir_alu_op_type alu_type,
	enum insert_position pos);

struct ir_insn *bpf_ir_create_loadraw_insn_cg(struct bpf_ir_env *env,
					      struct ir_insn *pos_insn,
					      enum ir_vr_type type,
					      struct ir_address_value val,
					      enum insert_position pos);

struct ir_insn *bpf_ir_create_loadraw_insn_bb_cg(struct bpf_ir_env *env,
						 struct ir_basic_block *pos_bb,
						 enum ir_vr_type type,
						 struct ir_address_value val,
						 enum insert_position pos);

struct ir_insn *bpf_ir_create_storeraw_insn_cg(struct bpf_ir_env *env,
					       struct ir_insn *pos_insn,
					       enum ir_vr_type type,
					       struct ir_address_value val,
					       struct ir_value to_store,
					       enum insert_position pos);

struct ir_insn *bpf_ir_create_storeraw_insn_bb_cg(struct bpf_ir_env *env,
						  struct ir_basic_block *pos_bb,
						  enum ir_vr_type type,
						  struct ir_address_value val,
						  struct ir_value to_store,
						  enum insert_position pos);

struct ir_insn *bpf_ir_create_assign_insn_cg(struct bpf_ir_env *env,
					     struct ir_insn *pos_insn,
					     struct ir_value val,
					     enum insert_position pos);

struct ir_insn *bpf_ir_create_assign_insn_bb_cg(struct bpf_ir_env *env,
						struct ir_basic_block *pos_bb,
						struct ir_value val,
						enum insert_position pos);

struct ir_insn *bpf_ir_create_assign_insn_norm(struct bpf_ir_env *env,
					       struct ir_insn *pos_insn,
					       struct ir_vr_pos dstpos,
					       struct ir_value val,
					       enum insert_position pos);

struct ir_insn *bpf_ir_create_assign_insn_bb_norm(struct bpf_ir_env *env,
						  struct ir_basic_block *pos_bb,
						  struct ir_vr_pos dstpos,
						  struct ir_value val,
						  enum insert_position pos);

struct ir_insn *bpf_ir_create_assign_insn_cg_v2(struct bpf_ir_env *env,
						struct ir_insn *pos_insn,
						struct ir_value val,
						enum insert_position pos);

struct ir_insn *bpf_ir_create_assign_insn_bb_cg_v2(
	struct bpf_ir_env *env, struct ir_basic_block *pos_bb,
	struct ir_value val, enum insert_position pos);

/* Instruction Constructors */

#endif
