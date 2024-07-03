#ifndef __BPF_IR_H__
#define __BPF_IR_H__

#include <linux/bpf.h>
#include <stddef.h>
#include "array.h"
#include "list.h"

/**
    Pre-IR instructions, similar to `bpf_insn`
 */
struct pre_ir_insn {
    __u8 opcode;

    __u8  dst_reg;
    __u8  src_reg;
    __s16 off;
    __s32 imm;
    __s64 imm64;  // signed immediate constant for 64-bit immediate

    size_t pos;  // Original position
};

/**
    IR Constants
 */
struct ir_constant {
    union {
        __u16 u16_d;
        __s16 s16_d;
        __u32 u32_d;
        __s32 s32_d;
        __u64 u64_d;
        __s64 s64_d;
    } data;
    enum {
        IR_CONSTANT_U16,
        IR_CONSTANT_S16,
        IR_CONSTANT_U32,
        IR_CONSTANT_S32,
        IR_CONSTANT_U64,
        IR_CONSTANT_S64,
    } type;
};

/**
    VALUE = CONSTANT | INSN | FUNCTIONARG | STACK_PTR

    "r1 = constant" pattern will use `CONSTANT` which will not be added to BB.
 */
struct ir_value {
    union {
        struct ir_constant constant_d;
        struct ir_insn    *insn_d;
        __u8               arg_id;
    } data;
    enum {
        IR_VALUE_CONSTANT,
        IR_VALUE_FUNCTIONARG,
        IR_VALUE_INSN,
        IR_VALUE_STACK_PTR,
    } type;
};

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

/**
    Virtual Register Type
 */
enum ir_vr_type {
    IR_VR_TYPE_U1,
    IR_VR_TYPE_U2,
    IR_VR_TYPE_U4,
    IR_VR_TYPE_U8,
    IR_VR_TYPE_S1,
    IR_VR_TYPE_S2,
    IR_VR_TYPE_S4,
    IR_VR_TYPE_S8,
    IR_VR_TYPE_PTR,
};

/**
    INSN =
          ALLOC <ir_vr_type>
        | STORE <value:ptr>, <value>
        | LOAD <ir_vr_type> <value:ptr>
        | STORERAW <ir_vr_type> <ir_address_value>, <value>
        | LOADRAW <ir_vr_type> <ir_address_value>
        | ADD <value>, <value>
        | SUB <value>, <value>
        | MUL <value>, <value>
        | MOV <value>
        | CALL <function id> <arg_num> <values...>
        | RET <value>
        | JA <bb>
        | JEQ <value>, <value>, <bb>
        | JGT <value>, <value>, <bb>
        | JGE <value>, <value>, <bb>
        | JLT <value>, <value>, <bb>
        | JLE <value>, <value>, <bb>
        | JNE <value>, <value>, <bb>
        | PHI <phi_value>
 */
struct ir_insn {
    struct ir_value v1;
    struct ir_value v2;

    // Used in CALL instructions
    struct ir_value v3;
    struct ir_value v4;

    // Used in ALLOC instructions
    enum ir_vr_type vr_type;

    // Used in RAW instructions
    struct ir_address_value addr_val;

    struct ir_basic_block *bb;

    // Array of phi_value
    struct array phi;

    __s32 fid;
    __u32 f_arg_num;
    enum {
        IR_INSN_ALLOC,
        IR_INSN_ALLOCP,
        IR_INSN_STORE,
        IR_INSN_LOAD,
        IR_INSN_STORERAW,
        IR_INSN_LOADRAW,
        // ALU
        IR_INSN_ADD,
        IR_INSN_SUB,
        IR_INSN_MUL,
        IR_INSN_MOV,  // mov
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
        IR_INSN_PHI
    } op;
    struct list_head       ptr;
    struct ir_basic_block *parent_bb;

    struct array users;

    // Might be useful?
    enum ir_vr_type type;
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
    struct array     preds;
    struct array     succs;

    // Used for construction and debugging
    struct pre_ir_basic_block *_pre_bb;
    __u8                       _visited;
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

#endif
