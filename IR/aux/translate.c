#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"

struct pre_ir_insn load_reg_to_reg(__u8 dst, __u8 src) {
    // MOV dst src
    struct pre_ir_insn insn;
    insn.opcode  = BPF_MOV | BPF_X | BPF_ALU64;
    insn.dst_reg = dst;
    insn.src_reg = src;
    return insn;
}

struct pre_ir_insn load_const_to_reg(__u8 dst, struct ir_constant c) {
    // MOV dst imm
    struct pre_ir_insn insn;
    insn.dst_reg = dst;
    if (c.type == IR_CONSTANT_U64) {
        insn.it     = IMM64;
        insn.imm64  = c.data.u64_d;
        insn.opcode = BPF_MOV | BPF_K | BPF_ALU64;
    }
    if (c.type == IR_CONSTANT_S64) {
        insn.it     = IMM64;
        insn.imm64  = c.data.s64_d;
        insn.opcode = BPF_MOV | BPF_K | BPF_ALU64;
    }
    if (c.type == IR_CONSTANT_U32) {
        insn.it     = IMM;
        insn.imm    = c.data.u32_d;
        insn.opcode = BPF_MOV | BPF_K | BPF_ALU;
    }
    if (c.type == IR_CONSTANT_S32) {
        insn.it     = IMM;
        insn.imm    = c.data.s32_d;
        insn.opcode = BPF_MOV | BPF_K | BPF_ALU;
    }
    if (c.type == IR_CONSTANT_U16) {
        insn.it     = IMM;
        insn.imm    = c.data.u16_d;
        insn.opcode = BPF_MOV | BPF_K | BPF_ALU;
    }
    if (c.type == IR_CONSTANT_S16) {
        insn.it     = IMM;
        insn.imm    = c.data.s16_d;
        insn.opcode = BPF_MOV | BPF_K | BPF_ALU;
    }
    return insn;
}

struct pre_ir_insn load_addr_to_reg(__u8 dst, struct ir_address_value addr, enum ir_vr_type type) {
    // MOV dst src
    struct pre_ir_insn insn;
    insn.dst_reg = dst;
    insn.off     = addr.offset;
    int size     = vr_type_to_size(type);
    if (addr.value.type == IR_VALUE_STACK_PTR) {
        insn.src_reg = BPF_REG_10;
        insn.opcode  = BPF_LDX | size | BPF_MEM;
    } else if (addr.value.type == IR_VALUE_INSN) {
        // Must be REG
        DBGASSERT(vtype(addr.value) == REG);
        // Load reg (addr) to reg
        insn.src_reg = insn_cg(addr.value.data.insn_d)->alloc_reg;
        insn.opcode  = BPF_LDX | size | BPF_MEM;
    } else if (addr.value.type == IR_VALUE_CONSTANT) {
        // Must be U64
        DBGASSERT(addr.value.data.constant_d.type == IR_CONSTANT_U64);
        insn.it     = IMM64;
        insn.imm64  = addr.value.data.constant_d.data.u64_d;
        insn.opcode = BPF_IMM | size | BPF_LD;
    } else {
        CRITICAL("Error");
    }
    return insn;
}

void translate(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_value          v0       = insn->values[0];
            struct ir_value          v1       = insn->values[1];
            enum val_type            t0       = insn->value_num >= 1 ? vtype(v0) : UNDEF;
            enum val_type            t1       = insn->value_num >= 2 ? vtype(v1) : UNDEF;
            enum val_type            tdst     = vtype_insn(insn);
            struct ir_insn_cg_extra *extra    = insn_cg(insn);
            struct ir_insn          *dst_insn = dst(insn);
            if (insn->op == IR_INSN_ALLOC) {
                // Nothing to do
                extra->translated_num = 0;
            } else if (insn->op == IR_INSN_STORE) {
                CRITICAL("Error");
            } else if (insn->op == IR_INSN_LOAD) {
                CRITICAL("Error");
            } else if (insn->op == IR_INSN_LOADRAW) {
                DBGASSERT(tdst == REG);
            } else if (insn->op == IR_INSN_STORERAW) {
            } else if (insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL) {
            } else if (insn->op == IR_INSN_ASSIGN) {
            } else if (insn->op == IR_INSN_RET) {
            } else if (insn->op == IR_INSN_CALL) {
            } else if (insn->op == IR_INSN_JA) {
            } else if (insn->op >= IR_INSN_JEQ && insn->op < IR_INSN_PHI) {
            } else {
                CRITICAL("No such instruction");
            }
        }
    }
}
