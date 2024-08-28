#ifndef _LINUX_BPF_IR_H
#define _LINUX_BPF_IR_H

#include <linux/bpf.h>

#ifndef __KERNEL__
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "list.h"
#include "read.h"
#include <stddef.h>

#define PRINT_LOG printf

#include "stdint.h"

#define SIZET_MAX SIZE_MAX

#else

#include <linux/types.h>
#include <linux/sort.h>

#define PRINT_LOG printk

#define SIZET_MAX ULONG_MAX

#define qsort(a, b, c, d) sort(a, b, c, d, NULL)

#endif

struct array {
	void *data;
	size_t num_elem; // Current length
	size_t max_elem; // Maximum length
	size_t elem_size;
};

void array_init(struct array *res, size_t size);

int array_push(struct array *, void *);

int array_push_unique(struct array *arr, void *data);

void array_free(struct array *);

struct array array_null(void);

void array_erase(struct array *arr, size_t idx);

void *array_get_void(struct array *arr, size_t idx);

#define array_get(arr, idx, type) ((type *)array_get_void(arr, idx))

int array_clear(struct array *arr);

int array_clone(struct array *res, struct array *arr);

#define array_for(pos, arr)                   \
	for (pos = ((typeof(pos))(arr.data)); \
	     pos < (typeof(pos))(arr.data) + arr.num_elem; pos++)

#define INIT_ARRAY(arr, type) array_init(arr, sizeof(type))

#ifndef __KERNEL__

#define CRITICAL(str)                                                          \
	{                                                                      \
		PRINT_LOG("%s:%d <%s> %s\n", __FILE__, __LINE__, __FUNCTION__, \
			  str);                                                \
		exit(1);                                                       \
	}

#else

#define CRITICAL(str)                                                      \
	{                                                                  \
		panic("%s:%d <%s> %s\n", __FILE__, __LINE__, __FUNCTION__, \
		      str);                                                \
	}

#endif

#define RAISE_ERROR(str)                                                       \
	{                                                                      \
		PRINT_LOG("%s:%d <%s> %s\n", __FILE__, __LINE__, __FUNCTION__, \
			  str);                                                \
		return -ENOSYS;                                                \
	}

#define DBGASSERT(cond)                       \
	if (!(cond)) {                        \
		CRITICAL("Assertion failed"); \
	}

void *malloc_proto(size_t size);

void free_proto(void *ptr);

#define SAFE_MALLOC(dst, size)            \
	{                                 \
		dst = malloc_proto(size); \
		if (!dst) {               \
			return -ENOMEM;   \
		}                         \
	}

#define MAX_FUNC_ARG 5

enum imm_type { IMM, IMM64 };

/**
    Pre-IR instructions, similar to `bpf_insn`
 */
struct pre_ir_insn {
	__u8 opcode;

	__u8 dst_reg;
	__u8 src_reg;
	__s16 off;

	enum imm_type it;
	__s32 imm;
	__s64 imm64; // Immediate constant for 64-bit immediate

	size_t pos; // Original position
};

enum ir_value_type {
	IR_VALUE_CONSTANT,
	IR_VALUE_CONSTANT_RAWOFF, // A constant value in raw operations to be added during code
	// generation
	IR_VALUE_INSN,
	IR_VALUE_STACK_PTR,
	IR_VALUE_UNDEF,
};

/**
    VALUE = CONSTANT | INSN

    "r1 = constant" pattern will use `CONSTANT` which will not be added to BB.
 */
struct ir_value {
	union {
		__s64 constant_d;
		struct ir_insn *insn_d;
	} data;
	enum ir_value_type type;
};

struct ir_value ir_value_insn(struct ir_insn *);

struct ir_value ir_value_stack_ptr(void);

/**
    Value plus an offset
 */
struct ir_address_value {
	// The value might be stack pointer
	struct ir_value value;
	__s16 offset;
};

/**
    A single phi value entry
 */
struct phi_value {
	struct ir_value value;
	struct ir_basic_block *bb;
};

enum ir_alu_type {
	IR_ALU_UNKNOWN, // To prevent from not manually setting this type
	IR_ALU_32,
	IR_ALU_64,
};

int valid_alu_type(enum ir_alu_type type);

/**
    Virtual Register Type
 */
enum ir_vr_type {
	IR_VR_TYPE_UNKNOWN, // To prevent from not manually setting this type
	IR_VR_TYPE_8,
	IR_VR_TYPE_16,
	IR_VR_TYPE_32,
	IR_VR_TYPE_64,
};

int valid_vr_type(enum ir_vr_type type);

enum ir_insn_type {
	IR_INSN_ALLOC,
	IR_INSN_STORE,
	IR_INSN_LOAD,
	IR_INSN_STORERAW,
	IR_INSN_LOADRAW,
	// ALU
	IR_INSN_ADD,
	IR_INSN_SUB,
	IR_INSN_MUL,
	IR_INSN_LSH,
	IR_INSN_MOD,
	// CALL EXIT
	IR_INSN_CALL,
	IR_INSN_RET,
	// JMP
	IR_INSN_JA,
	IR_INSN_JEQ,
	IR_INSN_JGT,
	IR_INSN_JGE,
	IR_INSN_JLT,
	IR_INSN_JLE,
	IR_INSN_JNE,
	// PHI
	IR_INSN_PHI,
	// Code-gen instructions
	IR_INSN_ASSIGN,
	IR_INSN_REG,
	// Special instructions
	IR_INSN_FUNCTIONARG, // The function argument store, not an actual instruction
};

/**
    INSN =
          ALLOC <ir_vr_type>
        | STORE <value:ptr>, <value>
        | LOAD <value:ptr>
        | STORERAW <ir_vr_type> <ir_address_value>, <value>
        | LOADRAW <ir_vr_type> <ir_address_value>

        | ADD <value>, <value>
        | SUB <value>, <value>
        | MUL <value>, <value>
        | LSH <value>, <value>
        | MOD <value>, <value>
        | CALL <function id> <values...>
        | RET <value>
        | JA <bb>
        | JEQ <value>, <value>, <bb_next>, <bb>
        | JGT <value>, <value>, <bb_next>, <bb>
        | JGE <value>, <value>, <bb_next>, <bb>
        | JLT <value>, <value>, <bb_next>, <bb>
        | JLE <value>, <value>, <bb_next>, <bb>
        | JNE <value>, <value>, <bb_next>, <bb>
        | PHI <phi_value>
        (For code gen usage)
        | ASSIGN <value>
        | REG
        (For special usage)
        | FUNCTIONARG <fid>

    Note. <bb_next> must be the next basic block.
    ASSIGN dst cannot be callee-saved registers
 */
struct ir_insn {
	struct ir_value values[MAX_FUNC_ARG];
	__u8 value_num;

	// Used in ALLOC and instructions
	enum ir_vr_type vr_type;

	// Used in RAW instructions
	struct ir_address_value addr_val;

	// ALU Type
	enum ir_alu_type alu;

	// Used in JMP instructions
	struct ir_basic_block *bb1;
	struct ir_basic_block *bb2;

	// Array of phi_value
	struct array phi;

	__s32 fid;
	enum ir_insn_type op;

	// Linked list
	struct list_head list_ptr;

	// Parent BB
	struct ir_basic_block *parent_bb;

	// Array of struct ir_insn *
	// Users
	struct array users;

	// Used when generating the real code
	size_t _insn_id;
	void *user_data;
	__u8 _visited;
};

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

	__u8 visited;

	__u8 sealed;
	__u8 filled;
	struct ir_basic_block *ir_bb;
	struct ir_insn *incompletePhis[MAX_BPF_REG];
};

/**
    IR Basic Block
 */
struct ir_basic_block {
	struct list_head ir_insn_head;

	// Array of struct ir_basic_block *
	struct array preds;

	// Array of struct ir_basic_block *
	struct array succs;

	// Used for construction and debugging
	__u8 _visited;
	size_t _id;
	void *user_data;

	// Array of struct ir_insn *
	struct array users;
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

	// Stack pointer (r10) users
	struct array sp_users;
	// Function argument
	struct ir_insn *function_arg[MAX_FUNC_ARG];
};

struct error {
	__u8 is_kernel_err : 1;
	unsigned int errorno : 31;
};

// helper functions

void write_variable(struct ssa_transform_env *env, __u8 reg,
		    struct pre_ir_basic_block *bb, struct ir_value val);

struct ir_value read_variable_recursive(struct ssa_transform_env *env, __u8 reg,
					struct pre_ir_basic_block *bb);

struct ir_value read_variable(struct ssa_transform_env *env, __u8 reg,
			      struct pre_ir_basic_block *bb);

void construct_ir(struct bpf_insn *insns, size_t len);

int gen_bb(struct bb_info *ret, struct bpf_insn *insns, size_t len);

struct ir_insn *add_phi_operands(struct ssa_transform_env *env, __u8 reg,
				 struct ir_insn *insn);

struct ir_insn *create_insn_back(struct ir_basic_block *bb);

struct ir_insn *create_insn_front(struct ir_basic_block *bb);

void add_user(struct ssa_transform_env *env, struct ir_insn *user,
	      struct ir_value val);

__u8 ir_value_equal(struct ir_value a, struct ir_value b);

struct ir_basic_block *init_ir_bb_raw(void);

int vr_type_to_size(enum ir_vr_type type);

/* Fun Start */

struct code_gen_info {
	// All vertex in interference graph
	// Array of struct ir_insn*
	struct array all_var;

	// BPF Register Virtual Instruction (used as dst)
	struct ir_insn *regs[MAX_BPF_REG];

	size_t callee_num;

	__s16 stack_offset;

	// Number of instructions
	size_t prog_size;

	struct bpf_insn *prog;

	// Whether to spill callee saved registers
	__u8 spill_callee;
};

struct ir_function {
	size_t arg_num;

	// Array of struct ir_basic_block *
	struct array all_bbs;

	// The entry block
	struct ir_basic_block *entry;

	// Store any information about the function
	struct array reachable_bbs;

	// BBs who has no successors
	struct array end_bbs;

	// Stack pointer (r10) users. Should be readonly. No more manual stack access should be allowed.
	struct array sp_users;

	// Function argument
	struct ir_insn *function_arg[MAX_FUNC_ARG];

	// Array of struct ir_constraint. Value constraints.
	struct array value_constraints;

	struct code_gen_info cg_info;
};

// Constructor and Destructor

int gen_function(struct ir_function *fun, struct ssa_transform_env *env);

void free_function(struct ir_function *fun);

void fix_bb_succ(struct ir_function *fun);

// IR checks

void prog_check(struct ir_function *fun);

void check_users(struct ir_function *fun);

/* Fun End */

/* BB Start */

/// Get the number of instructions in a basic block
size_t bb_len(struct ir_basic_block *);

struct ir_bb_cg_extra *bb_cg(struct ir_basic_block *bb);

struct ir_basic_block *create_bb(struct ir_function *fun);

void connect_bb(struct ir_basic_block *from, struct ir_basic_block *to);

void disconnect_bb(struct ir_basic_block *from, struct ir_basic_block *to);

/// Split a BB after an instruction
struct ir_basic_block *split_bb(struct ir_function *fun, struct ir_insn *insn);

struct ir_insn *get_last_insn(struct ir_basic_block *bb);

struct ir_insn *get_first_insn(struct ir_basic_block *bb);

int bb_empty(struct ir_basic_block *bb);

/* BB End */

/* IR Helper Start */

void clean_env_all(struct ir_function *fun);

void print_ir_prog(struct ir_function *);

void print_ir_prog_reachable(struct ir_function *fun);

void print_ir_prog_advanced(struct ir_function *,
			    void (*)(struct ir_basic_block *),
			    void (*)(struct ir_insn *),
			    void (*)(struct ir_insn *));

void print_ir_dst(struct ir_insn *insn);

void print_ir_alloc(struct ir_insn *insn);

void clean_env(struct ir_function *);

// Tag the instruction and BB
void tag_ir(struct ir_function *fun);

// Remove all tag information
void clean_tag(struct ir_function *);

void print_address_value(struct ir_address_value v);

void print_vr_type(enum ir_vr_type t);

void print_phi(struct array *phi);

void assign_id(struct ir_basic_block *bb, size_t *cnt, size_t *bb_cnt);

void print_ir_insn(struct ir_insn *);

void print_ir_value(struct ir_value v);

void print_raw_ir_insn(struct ir_insn *insn);

void print_raw_ir_bb(struct ir_basic_block *bb);

void print_insn_ptr_base(struct ir_insn *insn);

void print_ir_err_init(struct ir_function *fun);

void print_ir_insn_err(struct ir_insn *insn, char *msg);

void print_ir_bb_err(struct ir_basic_block *bb);

/* IR Helper End */

/* IR Instructions Start */

enum insert_position {
	INSERT_BACK,
	INSERT_FRONT,
	// BB-specific
	INSERT_BACK_BEFORE_JMP,
	INSERT_FRONT_AFTER_PHI
};

// Return an array of struct ir_value*
struct array get_operands(struct ir_insn *insn);

void replace_all_usage(struct ir_insn *insn, struct ir_value rep);

void replace_all_usage_except(struct ir_insn *insn, struct ir_value rep,
			      struct ir_insn *except);

void erase_insn(struct ir_insn *insn);

int is_last_insn(struct ir_insn *insn);

// Erase an instruction without checking the users
// Used in code gen
void erase_insn_raw(struct ir_insn *insn);

int is_void(struct ir_insn *insn);

int is_jmp(struct ir_insn *insn);

int is_cond_jmp(struct ir_insn *insn);

int is_alu(struct ir_insn *insn);

struct ir_insn *prev_insn(struct ir_insn *insn);

struct ir_insn *next_insn(struct ir_insn *insn);

struct ir_insn *create_alloc_insn(struct ir_insn *insn, enum ir_vr_type type,
				  enum insert_position pos);

struct ir_insn *create_alloc_insn_bb(struct ir_basic_block *bb,
				     enum ir_vr_type type,
				     enum insert_position pos);

struct ir_insn *create_store_insn(struct ir_insn *insn, struct ir_insn *st_insn,
				  struct ir_value val,
				  enum insert_position pos);

struct ir_insn *create_store_insn_bb(struct ir_basic_block *bb,
				     struct ir_insn *st_insn,
				     struct ir_value val,
				     enum insert_position pos);

struct ir_insn *create_load_insn(struct ir_insn *insn, struct ir_value val,
				 enum insert_position pos);

struct ir_insn *create_load_insn_bb(struct ir_basic_block *bb,
				    struct ir_value val,
				    enum insert_position pos);

struct ir_insn *create_bin_insn(struct ir_insn *insn, struct ir_value val1,
				struct ir_value val2, enum ir_insn_type ty,
				enum ir_alu_type aluty,
				enum insert_position pos);

struct ir_insn *create_bin_insn_bb(struct ir_basic_block *bb,
				   struct ir_value val1, struct ir_value val2,
				   enum ir_insn_type ty, enum ir_alu_type aluty,
				   enum insert_position pos);

struct ir_insn *create_ja_insn(struct ir_insn *insn,
			       struct ir_basic_block *to_bb,
			       enum insert_position pos);

struct ir_insn *create_ja_insn_bb(struct ir_basic_block *bb,
				  struct ir_basic_block *to_bb,
				  enum insert_position pos);

struct ir_insn *create_jbin_insn(struct ir_insn *insn, struct ir_value val1,
				 struct ir_value val2,
				 struct ir_basic_block *to_bb1,
				 struct ir_basic_block *to_bb2,
				 enum ir_insn_type ty, enum ir_alu_type aluty,
				 enum insert_position pos);

struct ir_insn *
create_jbin_insn_bb(struct ir_basic_block *bb, struct ir_value val1,
		    struct ir_value val2, struct ir_basic_block *to_bb1,
		    struct ir_basic_block *to_bb2, enum ir_insn_type ty,
		    enum ir_alu_type aluty, enum insert_position pos);

struct ir_insn *create_ret_insn(struct ir_insn *insn, struct ir_value val,
				enum insert_position pos);

struct ir_insn *create_ret_insn_bb(struct ir_basic_block *bb,
				   struct ir_value val,
				   enum insert_position pos);

struct ir_insn *create_assign_insn(struct ir_insn *insn, struct ir_value val,
				   enum insert_position pos);

struct ir_insn *create_assign_insn_bb(struct ir_basic_block *bb,
				      struct ir_value val,
				      enum insert_position pos);

struct ir_insn *create_phi_insn(struct ir_insn *insn, enum insert_position pos);

struct ir_insn *create_phi_insn_bb(struct ir_basic_block *bb,
				   enum insert_position pos);

void phi_add_operand(struct ir_insn *insn, struct ir_basic_block *bb,
		     struct ir_value val);

void val_add_user(struct ir_value val, struct ir_insn *user);

void val_remove_user(struct ir_value val, struct ir_insn *user);

struct ir_insn *create_assign_insn_cg(struct ir_insn *insn, struct ir_value val,
				      enum insert_position pos);

struct ir_insn *create_assign_insn_bb_cg(struct ir_basic_block *bb,
					 struct ir_value val,
					 enum insert_position pos);

void replace_operand(struct ir_insn *insn, struct ir_value v1,
		     struct ir_value v2);

struct ir_insn *create_insn_base_cg(struct ir_basic_block *bb);

struct ir_insn *create_insn_base(struct ir_basic_block *bb);

void insert_at(struct ir_insn *new_insn, struct ir_insn *insn,
	       enum insert_position pos);

void insert_at_bb(struct ir_insn *new_insn, struct ir_basic_block *bb,
		  enum insert_position pos);

/* IR Instructions End */

/* Passes Start */

void remove_trivial_phi(struct ir_function *fun);

void cut_bb(struct ir_function *fun);

void add_counter(struct ir_function *fun);

void add_constraint(struct ir_function *fun);

void gen_reachable_bbs(struct ir_function *);

void gen_end_bbs(struct ir_function *fun);

struct function_pass {
	void (*pass)(struct ir_function *);
	char name[30];
};

#define DEF_FUNC_PASS(fun, msg) { .pass = fun, .name = msg }

/**
    All function passes.
 */
static const struct function_pass passes[] = {
	DEF_FUNC_PASS(remove_trivial_phi, "Remove the trival Phi"),
	DEF_FUNC_PASS(add_counter, "Adding counter"),
};

/* Passes End */

/* Prog Check Start */

void check_jumping(struct ir_function *fun);

void cg_prog_check(struct ir_function *fun);

/* Prog Check End */

/* Code Gen Start */

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

int init_insn_cg(struct ir_insn *insn);

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

/* Code Gen End */

/* Constraint Start */

enum constraint_type {
	CONSTRAINT_TYPE_VALUE_EQUAL,
	CONSTRAINT_TYPE_VALUE_RANGE
};

struct ir_constraint {
	enum constraint_type type;

	// Range: [start, end)
	struct ir_value start;
	struct ir_value end;

	// Constrain value
	struct ir_value cval;

	// Real value to be compared
	struct ir_value val;
	struct ir_insn *pos;
};

/* Constraint End */

#endif
