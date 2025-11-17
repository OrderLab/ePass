/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_IR_H
#define _LINUX_BPF_IR_H

#include "linux/bpf.h"

#ifndef __KERNEL__

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

// Used to simulate kernel functions
#include "list.h"
#include "hash.h"

#define PRINT_DBG printf

#define CRITICAL(str)                                                       \
	{                                                                   \
		printf("%s:%d <%s> %s\n", __FILE__, __LINE__, __FUNCTION__, \
		       str);                                                \
		exit(1);                                                    \
	}

#else

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hash.h>

#define PRINT_DBG printk

#define CRITICAL(str)                                                      \
	{                                                                  \
		panic("%s:%d <%s> %s\n", __FILE__, __LINE__, __FUNCTION__, \
		      str);                                                \
	}

#endif

/**
 * define BPF_IR_LOG_SIZE - Maximum size of the BPF IR log buffer
 */
#define BPF_IR_LOG_SIZE 100000

/**
 * define BPF_IR_MAX_PASS_NAME_SIZE - Maximum length of a BPF IR pass name
 */
#define BPF_IR_MAX_PASS_NAME_SIZE 32

#define MAX_FUNC_ARG 5

/* IR Env Start */

// A environment for communicating with external functions

struct custom_pass_cfg;
struct builtin_pass_cfg;

/**
 * struct bpf_ir_opts - Options for BPF IR processing
 * @force: Force the use of ePass, even if the verifier passes
 * @enable_printk_log: Enable printing log messages using printk
 * @enable_throw_msg: Write an error message to trace when throwing an error
 * @fake_run: Run without actually modifying the bytecode
 * @print_only: Print IR without performing transformations
 * @max_insns: Maximum number of instructions to process
 * @dotgraph: Generate a DOT graph for the interference graph
 * @verbose: Verbosity level
 * @disable_prog_check: Disable program checks
 * @max_iteration: Maximum number of iterations allowed
 * @print_mode: Printing mode for the IR (e.g., BPF, detail, dump)
 * @custom_passes: Pointer to an array of custom pass configurations
 * @custom_pass_num: Number of custom passes
 * @builtin_pass_cfg: Pointer to an array of built-in pass configurations
 * @builtin_pass_cfg_num: Number of built-in pass configurations
 *
 * This struct defines the set of options used during the intermediate
 * representation (IR) processing of BPF programs. These options control
 * transformations, output formats, logging, and optimization behavior.
 */
struct bpf_ir_opts {
	bool force;
	bool enable_printk_log;
	bool enable_throw_msg;
	bool fake_run;
	bool print_only;
	u32 max_insns;
	bool dotgraph;
	int verbose;
	bool disable_prog_check;
	u32 max_iteration;

	enum {
		BPF_IR_PRINT_BPF,
		BPF_IR_PRINT_DETAIL,
		BPF_IR_PRINT_BPF_DETAIL,
		BPF_IR_PRINT_DUMP,
	} print_mode;

	struct custom_pass_cfg *custom_passes;
	size_t custom_pass_num;

	struct builtin_pass_cfg *builtin_pass_cfg;
	size_t builtin_pass_cfg_num;
};

/**
 * bpf_ir_default_opts - Get default BPF IR options
 *
 * Returns the default-initialized set of options for BPF IR processing.
 * These defaults are used to configure the IR pipeline when no custom
 * settings are provided.
 *
 * Return: A struct bpf_ir_opts containing default configuration values.
 */
struct bpf_ir_opts bpf_ir_default_opts(void);

/**
 * struct bpf_ir_env - Environment for BPF IR processing
 * @err: Internal error code
 * @insn_cnt: Number of BPF instructions
 * @insns: Pointer to the array of BPF instructions
 * @log: Log buffer for BPF IR processing output
 * @log_pos: Current position in the log buffer
 * @opts: Options used during BPF IR processing
 * @lift_time: Time spent lifting bytecode to IR
 * @run_time: Time spent running IR passes
 * @cg_time: Time spent in code generation
 * @executed: Whether the IR pipeline has executed (used in verifier)
 * @verifier_err: Error code from the verifier
 * @verifier_log_end_pos: Position in the verifier log buffer where logging ended
 * @prog_type: BPF program type; may be unspecified in user space
 * @venv: Pointer to the verifier environment
 * @verifier_info_map: Mapping from bytecode instruction number to verifier info
 *
 * This struct contains the complete state and metadata for processing
 * a BPF program in the intermediate representation (IR) pipeline.
 * It includes instructions, options, logging buffers, stats, and
 * verifier-related metadata.
 */
struct bpf_ir_env {
	int err;
	size_t insn_cnt;
	struct bpf_insn *insns;

	char log[BPF_IR_LOG_SIZE];
	size_t log_pos;

	struct bpf_ir_opts opts;

	u64 lift_time;
	u64 run_time;
	u64 cg_time;

	bool executed;
	int verifier_err;
	u64 verifier_log_end_pos;

	enum bpf_prog_type prog_type;
	void *venv;

	void *verifier_info_map;
};

/**
 * bpf_ir_print_to_log - Print a formatted log message to the BPF IR environment log
 * @level: Log verbosity level (e.g. 0 = error, 3 = info)
 * @env: Pointer to the BPF IR environment
 * @fmt: Format string (printf-style)
 * @...: Variable arguments for the format string
 *
 * Appends a formatted log message to the log buffer of the given IR environment.
 * Used mostly internally. Use PRINT_LOG_INFO() and related functions to print.
 */
void bpf_ir_print_to_log(int level, struct bpf_ir_env *env, char *fmt, ...);

/**
  * bpf_ir_reset_env - Reset the BPF IR environment to initial state
  * @env: Pointer to the BPF IR environment to reset
  *
  * Clears the execution state to prepare for a new IR processing run.
  */
void bpf_ir_reset_env(struct bpf_ir_env *env);

/**
  * PRINT_LOG_INFO - Print an informational message to the BPF IR log
  */
#define PRINT_LOG_INFO(...) bpf_ir_print_to_log(3, __VA_ARGS__)

/**
  * PRINT_LOG_DEBUG - Print a debug message to the BPF IR log
  */
#define PRINT_LOG_DEBUG(...) bpf_ir_print_to_log(2, __VA_ARGS__)

/**
  * PRINT_LOG_WARNING - Print a warning message to the BPF IR log
  */
#define PRINT_LOG_WARNING(...) bpf_ir_print_to_log(1, __VA_ARGS__)

/**
  * PRINT_LOG_ERROR - Print an error message to the BPF IR log
  */
#define PRINT_LOG_ERROR(...) bpf_ir_print_to_log(0, __VA_ARGS__)

/**
  * bpf_ir_print_log_dbg - Print the current IR log content for debugging
  * @env: Pointer to the BPF IR environment
  *
  * Outputs the current content of the IR log buffer for debugging purposes.
  * Use printf in userspace and printk in kernel
  */
void bpf_ir_print_log_dbg(struct bpf_ir_env *env);

/* IR Env End */

/* Array Start */

typedef struct array {
	void *data;
	size_t num_elem; // Current length
	size_t max_elem; // Maximum length
	size_t elem_size;
} array;

void bpf_ir_array_init(struct array *res, size_t size);

void bpf_ir_array_push(struct bpf_ir_env *env, struct array *, void *);

void bpf_ir_array_push_unique(struct bpf_ir_env *env, struct array *arr,
			      void *data);

void bpf_ir_array_free(struct array *);

struct array bpf_ir_array_null(void);

void bpf_ir_array_merge(struct bpf_ir_env *env, struct array *a,
			struct array *b);

void bpf_ir_array_erase(struct array *arr, size_t idx);

void *bpf_ir_array_get_void(struct array *arr, size_t idx);

#define array_get(arr, idx, type) ((type *)bpf_ir_array_get_void(arr, idx))

void bpf_ir_array_clear(struct bpf_ir_env *env, struct array *arr);

void bpf_ir_array_clone(struct bpf_ir_env *env, struct array *res,
			struct array *arr);

#define array_for(pos, arr)                   \
	for (pos = ((typeof(pos))(arr.data)); \
	     pos < (typeof(pos))(arr.data) + arr.num_elem; pos++)

#define INIT_ARRAY(arr, type) bpf_ir_array_init(arr, sizeof(type))

#define INIT_PTRSET_DEF(set) bpf_ir_ptrset_init(env, set, 8)

/* Array End */

/* Ptrset Start */

struct ptrset_entry {
	void *key;
	s8 occupy; // 0: Empty, 1: Occupied, -1: Deleted
};

struct ptrset {
	struct ptrset_entry *set;
	size_t size;
	size_t cnt;
};

void bpf_ir_ptrset_init(struct bpf_ir_env *env, struct ptrset *res,
			size_t size);

void bpf_ir_ptrset_insert(struct bpf_ir_env *env, struct ptrset *set,
			  void *key);

int bpf_ir_ptrset_delete(struct ptrset *set, void *key);

bool bpf_ir_ptrset_exists(struct ptrset *set, void *key);

void bpf_ir_ptrset_print_dbg(struct bpf_ir_env *env, struct ptrset *set,
			     void (*print_key)(struct bpf_ir_env *env, void *));

void bpf_ir_ptrset_clean(struct ptrset *set);

void bpf_ir_ptrset_free(struct ptrset *set);

void **bpf_ir_ptrset_next(struct ptrset *set, void **keyd);

struct ptrset bpf_ir_ptrset_union(struct bpf_ir_env *env, struct ptrset *set1,
				  struct ptrset *set2);

struct ptrset bpf_ir_ptrset_intersec(struct bpf_ir_env *env,
				     struct ptrset *set1, struct ptrset *set2);

void bpf_ir_ptrset_move(struct ptrset *set1, struct ptrset *set2);

void bpf_ir_ptrset_clone(struct bpf_ir_env *env, struct ptrset *set1,
			 struct ptrset *set2);

void bpf_ir_ptrset_add(struct bpf_ir_env *env, struct ptrset *set1,
		       struct ptrset *set2);

void bpf_ir_ptrset_minus(struct ptrset *set1, struct ptrset *set2);

#define ptrset_for(pos, set)                                           \
	for (pos = (typeof(pos))bpf_ir_ptrset_next(&(set), NULL); pos; \
	     pos = (typeof(pos))bpf_ir_ptrset_next(&(set), (void **)pos))

/* Ptrset End */

/* DBG Macro Start */

#define RAISE_ERROR(str)                                                    \
	{                                                                   \
		PRINT_LOG_ERROR(env, "\e[1;31mError: %s:%d <%s> %s\e[0m\n", \
				__FILE__, __LINE__, __FUNCTION__, str);     \
		env->err = -ENOSYS;                                         \
		return;                                                     \
	}

#define RAISE_ERROR_RET(str, ret)                                           \
	{                                                                   \
		PRINT_LOG_ERROR(env, "\e[1;31mError: %s:%d <%s> %s\e[0m\n", \
				__FILE__, __LINE__, __FUNCTION__, str);     \
		env->err = -ENOSYS;                                         \
		return ret;                                                 \
	}

#define DBGASSERT(cond)                       \
	if (!(cond)) {                        \
		CRITICAL("Assertion failed"); \
	}

#define ASSERT_DUMP(cond, ret)                            \
	if (!(cond)) {                                    \
		RAISE_ERROR_RET("Assertion failed", ret); \
	}

#define CRITICAL_DUMP(env, str)            \
	{                                  \
		bpf_ir_print_log_dbg(env); \
		CRITICAL(str)              \
	}

#define CRITICAL_ASSERT(env, cond)                      \
	if (!(cond)) {                                  \
		CRITICAL_DUMP(env, "Assertion failed"); \
	}

/* DBG Macro End */

enum ir_alu_op_type {
	IR_ALU_UNKNOWN, // To prevent from not manually setting this type
	IR_ALU_32,
	IR_ALU_64,
};

enum ir_builtin_constant {
	IR_BUILTIN_NONE, // Not a builtin constant
	IR_BUILTIN_BB_INSN_CNT, // The number of instructions in the basic block (computed during code generation)
	IR_BUILTIN_BB_INSN_CRITICAL_CNT, // The number of instructions from the nearest critical block
};

enum ir_value_type {
	IR_VALUE_CONSTANT,
	// A constant value in raw operations to be added during code generation
	// e.g. if the const is 10, then after CG, it will be 10 + stack shift
	IR_VALUE_CONSTANT_RAWOFF,

	// e.g. if the const is 10, then after CG, it will be 10 - stack shift
	IR_VALUE_CONSTANT_RAWOFF_REV,
	IR_VALUE_INSN,
	IR_VALUE_FLATTEN_DST, // Used only in code generation
	IR_VALUE_UNDEF,
};

enum ir_raw_pos_type {
	IR_RAW_POS_IMM,
	IR_RAW_POS_DST,
	IR_RAW_POS_SRC,
	IR_RAW_POS_INSN, // Mapping to this instruction, not to a specific value
};

// The original position of this instruction or value in the bytecode
struct ir_raw_pos {
	bool valid;
	size_t pos;
	enum ir_raw_pos_type pos_t;
};

/* Actual position of a VR, used after RA in cg */
struct ir_vr_pos {
	// If this VR needs to be allocated (insn like store does not)
	bool allocated;
	u32 spilled_size; // Spilled
	u8 alloc_reg; // Not spilled
	s32 spilled; // 0 -> not spilled; X -> spilled at X
};

/*
 *  VALUE = CONSTANT | INSN
 *
 *  "r1 = constant" pattern will use `CONSTANT` which will not be added to BB.
 */
struct ir_value {
	union {
		s64 constant_d;
		struct ir_insn *insn_d;
		struct ir_vr_pos vr_pos;
	} data;
	enum ir_value_type type;
	enum ir_alu_op_type const_type; // Used when type is a constant
	enum ir_builtin_constant builtin_const;
	struct ir_raw_pos raw_pos;
	bool raw_stack; // If this is a SP, whether it is a raw stack pointer
};

/*
 * Value plus an offset
 */
struct ir_address_value {
	// The value might be stack pointer
	struct ir_value value;
	s16 offset;
	enum ir_value_type offset_type;
};

/*
 * A single phi value entry
 */
struct phi_value {
	struct ir_value value;
	struct ir_basic_block *bb;
};

/*
 * Virtual Register Type
 */
enum ir_vr_type {
	IR_VR_TYPE_UNKNOWN, // To prevent from not manually setting this type
	IR_VR_TYPE_8,
	IR_VR_TYPE_16,
	IR_VR_TYPE_32,
	IR_VR_TYPE_64,
};

enum ir_loadimm_extra_type {
	IR_LOADIMM_IMM64 = 0,
	IR_LOADIMM_MAP_BY_FD,
	IR_LOADIMM_MAP_VAL_FD,
	IR_LOADIMM_VAR_ADDR,
	IR_LOADIMM_CODE_ADDR,
	IR_LOADIMM_MAP_BY_IDX,
	IR_LOADIMM_MAP_VAL_IDX,
};

enum ir_insn_type {
	IR_INSN_ALLOC,
	IR_INSN_ALLOCARRAY,
	IR_INSN_GETELEMPTR,
	IR_INSN_STORE,
	IR_INSN_LOAD,
	IR_INSN_LOADIMM_EXTRA,
	IR_INSN_STORERAW,
	IR_INSN_LOADRAW,
	// Non-binary ALU
	IR_INSN_NEG,
	IR_INSN_HTOLE,
	IR_INSN_HTOBE,
	// Binay ALU
	IR_INSN_ADD,
	IR_INSN_SUB,
	IR_INSN_MUL,
	IR_INSN_DIV,
	IR_INSN_OR,
	IR_INSN_AND,
	IR_INSN_LSH,
	IR_INSN_ARSH,
	IR_INSN_RSH,
	IR_INSN_MOD,
	IR_INSN_XOR,
	// CALL EXIT
	IR_INSN_CALL,
	IR_INSN_RET,
	IR_INSN_THROW,
	// JMP
	IR_INSN_JA,
	IR_INSN_JEQ,
	IR_INSN_JGT,
	IR_INSN_JGE,
	IR_INSN_JLT,
	IR_INSN_JLE,
	IR_INSN_JNE,
	IR_INSN_JSGE,
	IR_INSN_JSLE,
	IR_INSN_JSGT,
	IR_INSN_JSLT,
	// PHI
	IR_INSN_PHI,
	// Code-gen instructions
	IR_INSN_ASSIGN,
	IR_INSN_REG,
	// Special instructions
	IR_INSN_FUNCTIONARG, // The function argument store, not an actual instruction
};

struct ir_insn {
	struct ir_value values[MAX_FUNC_ARG];
	u8 value_num;

	// Used in ALLOC and instructions
	enum ir_vr_type vr_type;

	// Used in RAW instructions
	struct ir_address_value addr_val;

	// ALU Operation Type
	enum ir_alu_op_type alu_op;

	// Used in JMP instructions
	struct ir_basic_block *bb1;
	struct ir_basic_block *bb2;

	// Array of phi_value
	struct array phi;

	union {
		s32 fid; // Function ID
		s32 fun_arg_id; // Function argument ID
		s32 reg_id; // Register ID
		u32 array_num; // Array number
		u32 swap_width; // Swap width for BPF_END
	};

	enum ir_loadimm_extra_type imm_extra_type; // For 64 imm load
	s64 imm64; // H (next_imm:32)(imm:32) L

	enum ir_insn_type op;

	// Linked list
	struct list_head list_ptr;

	// Parent BB
	struct ir_basic_block *parent_bb;

	// Array of struct ir_insn *
	// Users
	struct array users;

	// Raw position in bytecode
	struct ir_raw_pos raw_pos;

	// Used when generating the real code
	size_t _insn_id;
	void *user_data;
	u8 _visited;
};

enum ir_bb_flag {
	IR_BB_HAS_COUNTER = 1 << 0,
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
	u8 _visited;
	size_t _id;
	void *user_data;

	// Flag (experimental, may be removed in the future)
	u32 flag;
};

// Helper functions

struct ir_basic_block *bpf_ir_init_bb_raw(void);

// Main interface
void bpf_ir_autorun(struct bpf_ir_env *env);

struct ir_function *bpf_ir_lift(struct bpf_ir_env *env);

void bpf_ir_run(struct bpf_ir_env *env, struct ir_function *fun);

void bpf_ir_print_bpf_insn(struct bpf_ir_env *env, const struct bpf_insn *insn);

void bpf_ir_free_env(struct bpf_ir_env *env);

struct bpf_ir_env *bpf_ir_init_env(struct bpf_ir_opts opts,
				   const struct bpf_insn *insns, size_t len);

/* Fun Start */

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

	// Stack pointer
	struct ir_insn *sp;

	// Function argument
	struct ir_insn *function_arg[MAX_FUNC_ARG];

	void *user_data;
};

// Find IR instruction based on raw position
struct ir_insn *bpf_ir_find_ir_insn_by_rawpos(struct ir_function *fun,
					      size_t rawpos);

// IR checks

void bpf_ir_prog_check(struct bpf_ir_env *env, struct ir_function *fun);

/* Fun End */

void bpf_ir_free_function(struct ir_function *fun);

/* IR Instructions Start */

enum insert_position {
	INSERT_BACK,
	INSERT_FRONT,
	// BB-specific
	INSERT_BACK_BEFORE_JMP,
	INSERT_FRONT_AFTER_PHI
};

// Return an array of struct ir_value*
struct array bpf_ir_get_operands(struct bpf_ir_env *env, struct ir_insn *insn);

void bpf_ir_replace_all_usage(struct bpf_ir_env *env, struct ir_insn *insn,
			      struct ir_value rep);

void bpf_ir_replace_all_usage_except(struct bpf_ir_env *env,
				     struct ir_insn *insn, struct ir_value rep,
				     struct ir_insn *except);

void bpf_ir_erase_insn(struct bpf_ir_env *env, struct ir_insn *insn);

bool bpf_ir_is_last_insn(struct ir_insn *insn);

bool bpf_ir_is_void(struct ir_insn *insn);

bool bpf_ir_is_jmp(struct ir_insn *insn);

bool bpf_ir_is_commutative_alu(struct ir_insn *insn);

bool bpf_ir_is_cond_jmp(struct ir_insn *insn);

bool bpf_ir_is_bin_alu(struct ir_insn *insn);

struct ir_insn *bpf_ir_prev_insn(struct ir_insn *insn);

struct ir_insn *bpf_ir_next_insn(struct ir_insn *insn);

/* Instruction Constructors */

struct ir_insn *bpf_ir_create_alloc_insn(struct bpf_ir_env *env,
					 struct ir_insn *pos_insn,
					 enum ir_vr_type type,
					 enum insert_position pos);

struct ir_insn *bpf_ir_create_alloc_insn_bb(struct bpf_ir_env *env,
					    struct ir_basic_block *pos_bb,
					    enum ir_vr_type type,
					    enum insert_position pos);

struct ir_insn *bpf_ir_create_allocarray_insn(struct bpf_ir_env *env,
					      struct ir_insn *pos_insn,
					      enum ir_vr_type type, u32 num,
					      enum insert_position pos);

struct ir_insn *bpf_ir_create_allocarray_insn_bb(struct bpf_ir_env *env,
						 struct ir_basic_block *pos_bb,
						 enum ir_vr_type type, u32 num,
						 enum insert_position pos);

struct ir_insn *bpf_ir_create_loadimmextra_insn(
	struct bpf_ir_env *env, struct ir_insn *pos_insn,
	enum ir_loadimm_extra_type load_ty, s64 imm, enum insert_position pos);

struct ir_insn *bpf_ir_create_loadimmextra_insn_bb(
	struct bpf_ir_env *env, struct ir_basic_block *pos_bb,
	enum ir_loadimm_extra_type load_ty, s64 imm, enum insert_position pos);

struct ir_insn *bpf_ir_create_getelemptr_insn(struct bpf_ir_env *env,
					      struct ir_insn *pos_insn,
					      struct ir_insn *alloca_insn,
					      struct ir_value offset,
					      enum insert_position pos);

struct ir_insn *bpf_ir_create_getelemptr_insn_bb(struct bpf_ir_env *env,
						 struct ir_basic_block *pos_bb,
						 struct ir_insn *alloca_insn,
						 struct ir_value offset,
						 enum insert_position pos);

struct ir_insn *bpf_ir_create_neg_insn(struct bpf_ir_env *env,
				       struct ir_insn *pos_insn,
				       enum ir_alu_op_type alu_type,
				       struct ir_value val,
				       enum insert_position pos);

struct ir_insn *bpf_ir_create_neg_insn_bb(struct bpf_ir_env *env,
					  struct ir_basic_block *pos_bb,
					  enum ir_alu_op_type alu_type,
					  struct ir_value val,
					  enum insert_position pos);

struct ir_insn *bpf_ir_create_end_insn(struct bpf_ir_env *env,
				       struct ir_insn *pos_insn,
				       enum ir_insn_type ty, u32 swap_width,
				       struct ir_value val,
				       enum insert_position pos);

struct ir_insn *bpf_ir_create_end_insn_bb(struct bpf_ir_env *env,
					  struct ir_basic_block *pos_bb,
					  enum ir_insn_type ty, u32 swap_width,
					  struct ir_value val,
					  enum insert_position pos);

struct ir_insn *bpf_ir_create_store_insn(struct bpf_ir_env *env,
					 struct ir_insn *pos_insn,
					 struct ir_insn *insn,
					 struct ir_value val,
					 enum insert_position pos);

struct ir_insn *bpf_ir_create_store_insn_bb(struct bpf_ir_env *env,
					    struct ir_basic_block *pos_bb,
					    struct ir_insn *insn,
					    struct ir_value val,
					    enum insert_position pos);

struct ir_insn *bpf_ir_create_load_insn(struct bpf_ir_env *env,
					struct ir_insn *pos_insn,
					struct ir_value val,
					enum insert_position pos);

struct ir_insn *bpf_ir_create_load_insn_bb(struct bpf_ir_env *env,
					   struct ir_basic_block *pos_bb,
					   struct ir_value val,
					   enum insert_position pos);

struct ir_insn *
bpf_ir_create_bin_insn(struct bpf_ir_env *env, struct ir_insn *pos_insn,
		       struct ir_value val1, struct ir_value val2,
		       enum ir_insn_type ty, enum ir_alu_op_type alu_type,
		       enum insert_position pos);

struct ir_insn *
bpf_ir_create_bin_insn_bb(struct bpf_ir_env *env, struct ir_basic_block *pos_bb,
			  struct ir_value val1, struct ir_value val2,
			  enum ir_insn_type ty, enum ir_alu_op_type alu_type,
			  enum insert_position pos);

struct ir_insn *bpf_ir_create_ja_insn(struct bpf_ir_env *env,
				      struct ir_insn *pos_insn,
				      struct ir_basic_block *to_bb,
				      enum insert_position pos);

struct ir_insn *bpf_ir_create_ja_insn_bb(struct bpf_ir_env *env,
					 struct ir_basic_block *pos_bb,
					 struct ir_basic_block *to_bb,
					 enum insert_position pos);

struct ir_insn *
bpf_ir_create_jbin_insn(struct bpf_ir_env *env, struct ir_insn *pos_insn,
			struct ir_value val1, struct ir_value val2,
			struct ir_basic_block *to_bb1,
			struct ir_basic_block *to_bb2, enum ir_insn_type ty,
			enum ir_alu_op_type alu_type, enum insert_position pos);

struct ir_insn *
bpf_ir_create_jbin_insn_bb(struct bpf_ir_env *env,
			   struct ir_basic_block *pos_bb, struct ir_value val1,
			   struct ir_value val2, struct ir_basic_block *to_bb1,
			   struct ir_basic_block *to_bb2, enum ir_insn_type ty,
			   enum ir_alu_op_type alu_type,
			   enum insert_position pos);

struct ir_insn *bpf_ir_create_ret_insn(struct bpf_ir_env *env,
				       struct ir_insn *pos_insn,
				       struct ir_value val,
				       enum insert_position pos);

struct ir_insn *bpf_ir_create_ret_insn_bb(struct bpf_ir_env *env,
					  struct ir_basic_block *pos_bb,
					  struct ir_value val,
					  enum insert_position pos);

struct ir_insn *bpf_ir_create_throw_insn(struct bpf_ir_env *env,
					 struct ir_insn *pos_insn,
					 enum insert_position pos);

struct ir_insn *bpf_ir_create_throw_insn_bb(struct bpf_ir_env *env,
					    struct ir_basic_block *pos_bb,
					    enum insert_position pos);

struct ir_insn *bpf_ir_create_call_insn(struct bpf_ir_env *env,
					struct ir_insn *pos_insn, s32 fid,
					enum insert_position pos);

struct ir_insn *bpf_ir_create_call_insn_bb(struct bpf_ir_env *env,
					   struct ir_basic_block *pos_bb,
					   s32 fid, enum insert_position pos);

struct ir_insn *bpf_ir_create_loadraw_insn(struct bpf_ir_env *env,
					   struct ir_insn *pos_insn,
					   enum ir_vr_type type,
					   struct ir_address_value val,
					   enum insert_position pos);

struct ir_insn *bpf_ir_create_loadraw_insn_bb(struct bpf_ir_env *env,
					      struct ir_basic_block *pos_bb,
					      enum ir_vr_type type,
					      struct ir_address_value val,
					      enum insert_position pos);

struct ir_insn *
bpf_ir_create_storeraw_insn(struct bpf_ir_env *env, struct ir_insn *pos_insn,
			    enum ir_vr_type type, struct ir_address_value val,
			    struct ir_value to_store, enum insert_position pos);

struct ir_insn *bpf_ir_create_storeraw_insn_bb(struct bpf_ir_env *env,
					       struct ir_basic_block *pos_bb,
					       enum ir_vr_type type,
					       struct ir_address_value val,
					       struct ir_value to_store,
					       enum insert_position pos);

struct ir_insn *bpf_ir_create_assign_insn(struct bpf_ir_env *env,
					  struct ir_insn *pos_insn,
					  struct ir_value val,
					  enum insert_position pos);

struct ir_insn *bpf_ir_create_assign_insn_bb(struct bpf_ir_env *env,
					     struct ir_basic_block *pos_bb,
					     struct ir_value val,
					     enum insert_position pos);

struct ir_insn *bpf_ir_create_phi_insn(struct bpf_ir_env *env,
				       struct ir_insn *pos_insn,
				       enum insert_position pos);

struct ir_insn *bpf_ir_create_phi_insn_bb(struct bpf_ir_env *env,
					  struct ir_basic_block *pos_bb,
					  enum insert_position pos);

/* Instruction Constructors */

void bpf_ir_phi_add_operand(struct bpf_ir_env *env, struct ir_insn *insn,
			    struct ir_basic_block *bb, struct ir_value val);

void bpf_ir_add_call_arg(struct bpf_ir_env *env, struct ir_insn *insn,
			 struct ir_value val);

void bpf_ir_val_add_user(struct bpf_ir_env *env, struct ir_value val,
			 struct ir_insn *user);

void bpf_ir_val_remove_user(struct ir_value val, struct ir_insn *user);

void bpf_ir_replace_operand(struct bpf_ir_env *env, struct ir_insn *insn,
			    struct ir_value v1, struct ir_value v2);

struct ir_insn *bpf_ir_create_insn_base(struct bpf_ir_env *env,
					struct ir_basic_block *bb);

void bpf_ir_insert_at(struct ir_insn *new_insn, struct ir_insn *insn,
		      enum insert_position pos);

void bpf_ir_insert_at_bb(struct ir_insn *new_insn, struct ir_basic_block *bb,
			 enum insert_position pos);

/* IR Instructions End */

/* BB Start */

/// Get the number of instructions in a basic block
size_t bpf_ir_bb_len(struct ir_basic_block *);

struct ir_basic_block *bpf_ir_create_bb(struct bpf_ir_env *env,
					struct ir_function *fun);

void bpf_ir_connect_bb(struct bpf_ir_env *env, struct ir_basic_block *from,
		       struct ir_basic_block *to);

void bpf_ir_disconnect_bb(struct ir_basic_block *from,
			  struct ir_basic_block *to);

/// Split a BB
struct ir_basic_block *bpf_ir_split_bb(struct bpf_ir_env *env,
				       struct ir_function *fun,
				       struct ir_insn *insn,
				       enum insert_position insert_pos);

struct ir_insn *bpf_ir_get_last_insn(struct ir_basic_block *bb);

struct ir_insn *bpf_ir_get_first_insn(struct ir_basic_block *bb);

int bpf_ir_bb_empty(struct ir_basic_block *bb);

void bpf_ir_bb_create_error_block(struct bpf_ir_env *env,
				  struct ir_function *fun, struct ir_insn *insn,
				  enum insert_position insert_pos,
				  struct ir_basic_block **dst_err_bb,
				  struct ir_basic_block **dst_new_bb);

/* BB End */

/* IR Helper Start */

void bpf_ir_clean_metadata_all(struct ir_function *fun);

void print_ir_prog(struct bpf_ir_env *env, struct ir_function *);

void print_ir_prog_notag(struct bpf_ir_env *env, struct ir_function *fun);

void print_ir_prog_advanced(struct bpf_ir_env *env, struct ir_function *,
			    void (*)(struct bpf_ir_env *env,
				     struct ir_basic_block *),
			    void (*)(struct bpf_ir_env *env, struct ir_insn *),
			    void (*)(struct bpf_ir_env *env, struct ir_insn *));

void bpf_ir_clean_visited(struct ir_function *);

// Tag the instruction and BB
void tag_ir(struct ir_function *fun);

// Remove id
void bpf_ir_clean_id(struct ir_function *);

void print_address_value(struct bpf_ir_env *env, struct ir_address_value v);

void print_vr_type(struct bpf_ir_env *env, enum ir_vr_type t);

void print_phi(struct bpf_ir_env *env, struct array *phi);

void assign_id(struct ir_basic_block *bb, size_t *cnt, size_t *bb_cnt);

void print_ir_insn(struct bpf_ir_env *env, struct ir_insn *);

void print_ir_value(struct bpf_ir_env *env, struct ir_value v);

void print_raw_ir_insn(struct bpf_ir_env *env, struct ir_insn *insn);

void print_raw_ir_insn_full(struct bpf_ir_env *env, struct ir_insn *insn,
			    void (*print_ir)(struct bpf_ir_env *env,
					     struct ir_insn *));

void print_raw_ir_bb(struct bpf_ir_env *env, struct ir_basic_block *bb);

void print_insn_ptr_base(struct bpf_ir_env *env, struct ir_insn *insn);

void print_ir_err_init(struct ir_function *fun);

void print_ir_insn_err(struct bpf_ir_env *env, struct ir_insn *insn, char *msg);

void print_ir_insn_err_full(struct bpf_ir_env *env, struct ir_insn *insn,
			    char *msg,
			    void (*print_ir)(struct bpf_ir_env *env,
					     struct ir_insn *));

void print_ir_bb_err(struct bpf_ir_env *env, struct ir_basic_block *bb);

/* IR Helper End */

/* Passes Start */

void remove_trivial_phi(struct bpf_ir_env *env, struct ir_function *fun,
			void *param);

void insn_counter(struct bpf_ir_env *env, struct ir_function *fun, void *param);

void msan(struct bpf_ir_env *env, struct ir_function *fun, void *param);

void bpf_ir_div_by_zero(struct bpf_ir_env *env, struct ir_function *fun,
			void *param);

void bpf_ir_optimize_code_compaction(struct bpf_ir_env *env,
				     struct ir_function *fun, void *param);

void translate_throw(struct bpf_ir_env *env, struct ir_function *fun,
		     void *param);

struct function_pass {
	void (*pass)(struct bpf_ir_env *env, struct ir_function *, void *param);

	bool enabled;
	bool force_enable;
	char name[BPF_IR_MAX_PASS_NAME_SIZE];
};

extern const struct function_pass *pre_passes;
extern const size_t pre_passes_cnt;

extern const struct function_pass *post_passes;
extern const size_t post_passes_cnt;

struct custom_pass_cfg {
	struct function_pass pass;
	void *param;
	// Check if able to apply
	bool (*check_apply)(int err_code);

	// Load the param
	int (*param_load)(const char *, void **param);
	void (*param_unload)(void *param);
};

struct builtin_pass_cfg {
	char name[BPF_IR_MAX_PASS_NAME_SIZE];
	void *param;

	// Enable for one run
	bool enable;

	// Should be enabled for the last run
	bool enable_cfg;

	// Load the param
	int (*param_load)(const char *, void **param);
	void (*param_unload)(void *param);
};

#define DEF_CUSTOM_PASS(pass_def, check_applyc, param_loadc, param_unloadc) \
	{ .pass = pass_def,                                                 \
	  .param = NULL,                                                    \
	  .param_load = param_loadc,                                        \
	  .param_unload = param_unloadc,                                    \
	  .check_apply = check_applyc }

#define DEF_BUILTIN_PASS_CFG(namec, param_loadc, param_unloadc) \
	{ .name = namec,                                        \
	  .param = NULL,                                        \
	  .enable = false,                                      \
	  .enable_cfg = false,                                  \
	  .param_load = param_loadc,                            \
	  .param_unload = param_unloadc }

#define DEF_BUILTIN_PASS_ENABLE_CFG(namec, param_loadc, param_unloadc) \
	{ .name = namec,                                               \
	  .param = NULL,                                               \
	  .enable = true,                                              \
	  .enable_cfg = false,                                         \
	  .param_load = param_loadc,                                   \
	  .param_unload = param_unloadc }

#define DEF_FUNC_PASS(fun, msg, en_def) \
	{ .pass = fun, .name = msg, .enabled = en_def, .force_enable = false }

#define DEF_NON_OVERRIDE_FUNC_PASS(fun, msg) \
	{ .pass = fun, .name = msg, .enabled = true, .force_enable = true }

/* Passes End */

/* Code Gen Start */

void bpf_ir_compile(struct bpf_ir_env *env, struct ir_function *fun);

/* Code Gen End */

/* IR Value Start */

bool bpf_ir_value_equal(struct ir_value a, struct ir_value b);

struct ir_value bpf_ir_value_insn(struct ir_insn *);

struct ir_value bpf_ir_value_vrpos(struct ir_vr_pos pos);

struct ir_value bpf_ir_value_const32(s32 val);

struct ir_value bpf_ir_value_const64(s64 val);

struct ir_value bpf_ir_value_const32_rawoff(s32 val);

struct ir_value bpf_ir_value_const64_rawoff(s64 val);

struct ir_value bpf_ir_value_undef(void);

struct ir_address_value bpf_ir_addr_val(struct ir_value value, s16 offset);

struct ir_value bpf_ir_value_stack_ptr(struct ir_function *fun);

struct ir_value bpf_ir_value_r0(struct ir_function *fun);

#define VR_POS_STACK_PTR                             \
	(struct ir_vr_pos){ .allocated = true,       \
			    .alloc_reg = BPF_REG_10, \
			    .spilled = 0 }

struct ir_value bpf_ir_value_norm_stack_ptr(void);

void bpf_ir_change_value(struct bpf_ir_env *env, struct ir_insn *insn,
			 struct ir_value *old, struct ir_value new);

/* IR Value End */

/* Kern Utils Start */

int bpf_ir_init_opts(struct bpf_ir_env *env, const char *global_opt,
		     const char *pass_opt);

bool bpf_ir_builtin_pass_enabled(struct bpf_ir_env *env, const char *pass_name);

void bpf_ir_free_opts(struct bpf_ir_env *env);

/* Kern Utils End */

#endif
