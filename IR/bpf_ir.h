#ifndef __BPF_IR_H__
#define __BPF_IR_H__

#include <linux/bpf.h>
#include <stddef.h>
#include "array.h"
#include "list.h"
// #include <linux/types.h>

void                       construct_ir(struct bpf_insn *insns, size_t len);
struct pre_ir_basic_block *gen_bb(struct bpf_insn *insns, size_t len);
// First stage, transform to a pre-IR code

struct pre_ir_insn {
    __u8 code;
    __u8 source;
    __u8 instruction_class;

    __u8  dst_reg;
    __u8  src_reg;
    __s16 off;
    __s32 imm;
    __s64 imm64; /* signed immediate constant for 64-bit immediate */
};

struct ir_insn;
struct pre_ir_basic_block {
    size_t              id;
    size_t              start_pos;
    size_t              end_pos;
    size_t              len;
    struct pre_ir_insn *pre_insns;
    struct ir_insn     *ir_insns;

    struct array               preds;
    struct array               succs;
    struct pre_ir_basic_block *self;
    __u8                       visited;
};

// Second stage, transform to IR

struct ir_constant {
    union {
        __u32 u32_d;
        __s32 s32_d;
        __u64 u64_d;
        __s64 s64_d;
    } data;
    enum {
        IR_CONSTANT_U32,
        IR_CONSTANT_S32,
        IR_CONSTANT_U64,
        IR_CONSTANT_S64,
        IR_CONSTANT_STACK_ADDR,
    } type;
};

/**
    VALUE = CONSTANT | INSN

    "r1 = constant" pattern will use `CONSTANT` which will not be added to BB.
 */
struct ir_value {
    union {
        struct ir_constant constant_d;
        struct ir_insn    *insn_d;
    } data;
    enum {
        IR_VALUE_CONSTANT,
        IR_VALUE_INSN,
    } type;
};

/**
    INSN =
          ALLOC <size in bytes>
        | ALLOCP <size in bytes> <stack position>
        | STORE <value>, <value>
        | LOAD <value>
        | ADD <value>, <value>
        | SUB <value>, <value>
        | MUL <value>, <value>
        | MOV <value>
        | CALL <value>
        | EXIT
        | JA <value>
        | JEQ <value>, <value>
        | JGT <value>, <value>
        | JGE <value>, <value>
        | JLT <value>, <value>
        | JLE <value>, <value>
        | JNE <value>, <value>
 */
struct ir_insn {
    ir_value v1;
    ir_value v2;

    // Used in ALLOC instructions
    __u32 alloc_size;
    __u32 stack_pos;
    enum {
        IR_INSN_ALLOC,   // alloc <size in bytes>
        IR_INSN_ALLOCP,  // alloc <size in bytes> <stack position>
        IR_INSN_STORE,   // store <value>, <value>
        IR_INSN_LOAD,    // load <value>
        // ALU
        IR_INSN_ADD,  // add <value>, <value>
        IR_INSN_SUB,  // sub <value>, <value>
        IR_INSN_MUL,
        IR_INSN_MOV,  // mov
        // CALL EXIT
        IR_INSN_CALL,
        IR_INSN_EXIT,
        // JMP
        IR_INSN_JA,
        IR_INSN_JEQ,
        IR_INSN_JGT,
        IR_INSN_JGE,
        IR_INSN_JLT,
        IR_INSN_JLE,
        IR_INSN_JNE,
    } op;
    struct list_head ptr;
};

/**
    IR Basic Block
 */
struct ir_basic_block {
    struct list_head ir_insn_head;
    struct array     preds;
    struct array     succs;
};

#endif
