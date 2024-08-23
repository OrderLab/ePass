#ifndef __BPF_IR_H__
#define __BPF_IR_H__

#include <linux/bpf.h>
#include <stddef.h>
#include "array.h"
#include "list.h"

#define MAX_FUNC_ARG 5

enum imm_type {
    IMM,
    IMM64
};

/**
    Pre-IR instructions, similar to `bpf_insn`
 */
struct pre_ir_insn {
    __u8 opcode;

    __u8  dst_reg;
    __u8  src_reg;
    __s16 off;

    enum imm_type it;
    __s32         imm;
    __s64         imm64;  // Immediate constant for 64-bit immediate

    size_t pos;  // Original position
};

enum ir_value_type {
    IR_VALUE_CONSTANT,
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
        __s64           constant_d;
        struct ir_insn *insn_d;
    } data;
    enum ir_value_type type;
};

struct ir_value ir_value_insn(struct ir_insn *);

struct ir_value ir_value_stack_ptr();

/**
    Value plus an offset
 */
struct ir_address_value {
    // The value might be stack pointer
    struct ir_value value;
    __s16           offset;
};

/**
    A single phi value entry
 */
struct phi_value {
    struct ir_value        value;
    struct ir_basic_block *bb;
};

enum ir_alu_type {
    IR_ALU_UNKNOWN,  // To prevent from not manually setting this type
    IR_ALU_32,
    IR_ALU_64,
};

/**
    Virtual Register Type
 */
enum ir_vr_type {
    IR_VR_TYPE_8,
    IR_VR_TYPE_16,
    IR_VR_TYPE_32,
    IR_VR_TYPE_64,
};

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
    IR_INSN_FUNCTIONARG,  // The function argument store, not an actual instruction
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
    __u8            value_num;

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

    __s32             fid;
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
    void  *user_data;
    __u8   _visited;
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

    __u8                   sealed;
    __u8                   filled;
    struct ir_basic_block *ir_bb;
    struct ir_insn        *incompletePhis[MAX_BPF_REG];
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
    __u8   _visited;
    size_t _id;
    void  *user_data;

    // Array of struct ir_insn *
    struct array users;
};

/**
    The BB value used in currentDef
 */
struct bb_val {
    struct pre_ir_basic_block *bb;
    struct ir_value            val;
};

/**
    BB with the raw entrance position
 */
struct bb_entrance_info {
    size_t                     entrance;
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
    struct array   currentDef[MAX_BPF_REG];
    struct bb_info info;

    // Stack pointer (r10) users
    struct array sp_users;
    // Function argument
    struct ir_insn *function_arg[MAX_FUNC_ARG];
};

struct error {
    __u8         is_kernel_err : 1;
    unsigned int errorno       : 31;
};

// helper functions

void write_variable(struct ssa_transform_env *env, __u8 reg, struct pre_ir_basic_block *bb,
                    struct ir_value val);

struct ir_value read_variable_recursive(struct ssa_transform_env *env, __u8 reg,
                                        struct pre_ir_basic_block *bb);

struct ir_value read_variable(struct ssa_transform_env *env, __u8 reg,
                              struct pre_ir_basic_block *bb);

void construct_ir(struct bpf_insn *insns, size_t len);

struct bb_info gen_bb(struct bpf_insn *insns, size_t len);

struct ir_insn *add_phi_operands(struct ssa_transform_env *env, __u8 reg, struct ir_insn *insn);

struct ir_insn *create_insn_back(struct ir_basic_block *bb);

struct ir_insn *create_insn_front(struct ir_basic_block *bb);

void add_user(struct ssa_transform_env *env, struct ir_insn *user, struct ir_value val);

__u8 ir_value_equal(struct ir_value a, struct ir_value b);

struct ir_basic_block *init_ir_bb_raw();

int vr_type_to_size(enum ir_vr_type type);

#endif
