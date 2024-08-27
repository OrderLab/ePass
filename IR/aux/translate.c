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

struct pre_ir_insn load_const_to_reg(__u8 dst, __s64 data) {
    // MOV dst imm
    struct pre_ir_insn insn;
    insn.dst_reg = dst;
    insn.it      = IMM64;
    insn.imm64   = data;
    insn.opcode  = BPF_MOV | BPF_K | BPF_ALU64;
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
        insn.it     = IMM64;
        insn.imm64  = addr.value.data.constant_d;
        insn.opcode = BPF_IMM | size | BPF_LD;
    } else {
        CRITICAL("Error");
    }
    return insn;
}

struct pre_ir_insn store_reg_to_reg_mem(__u8 dst, __u8 src, __s16 offset, enum ir_vr_type type) {
    struct pre_ir_insn insn;
    int                size = vr_type_to_size(type);
    insn.src_reg            = src;
    insn.off                = offset;
    insn.opcode             = BPF_STX | size | BPF_MEM;
    insn.dst_reg            = dst;
    return insn;
}

struct pre_ir_insn store_const_to_reg_mem(__u8 dst, __s64 val, __s16 offset, enum ir_vr_type type) {
    struct pre_ir_insn insn;
    int                size = vr_type_to_size(type);
    insn.it                 = IMM;
    insn.imm                = val;
    insn.off                = offset;
    insn.opcode             = BPF_ST | size | BPF_MEM;
    insn.dst_reg            = dst;
    return insn;
}

int alu_code(enum ir_insn_type insn) {
    switch (insn) {
        case IR_INSN_ADD:
            return BPF_ADD;
        case IR_INSN_SUB:
            return BPF_SUB;
        case IR_INSN_MUL:
            return BPF_MUL;
        case IR_INSN_MOD:
            return BPF_MOD;
        case IR_INSN_LSH:
            return BPF_LSH;
        default:
            CRITICAL("Error");
    }
}

struct pre_ir_insn alu_reg(__u8 dst, __u8 src, enum ir_alu_type type, int opcode) {
    struct pre_ir_insn insn;
    insn.dst_reg  = dst;
    insn.src_reg  = src;
    int alu_class = type == IR_ALU_64 ? BPF_ALU64 : BPF_ALU;
    insn.opcode   = opcode | BPF_X | alu_class;
    return insn;
}

struct pre_ir_insn alu_imm(__u8 dst, __s64 src, enum ir_alu_type type, int opcode) {
    struct pre_ir_insn insn;
    insn.dst_reg  = dst;
    insn.src_reg  = src;
    int alu_class = type == IR_ALU_64 ? BPF_ALU64 : BPF_ALU;
    if (type == IR_ALU_64) {
        insn.it    = IMM64;
        insn.imm64 = src;
    } else {
        insn.it  = IMM;
        insn.imm = src;
    }
    insn.opcode = opcode | BPF_K | alu_class;
    return insn;
}

__u8 get_alloc_reg(struct ir_insn *insn) {
    return insn_cg(insn)->alloc_reg;
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
            extra->translated_num             = 1;  // Default: 1 instruction
            if (insn->op == IR_INSN_ALLOC) {
                // Nothing to do
                extra->translated_num = 0;
            } else if (insn->op == IR_INSN_STORE) {
                CRITICAL("Error");
            } else if (insn->op == IR_INSN_LOAD) {
                CRITICAL("Error");
            } else if (insn->op == IR_INSN_LOADRAW) {
                DBGASSERT(tdst == REG);
                extra->translated[0] =
                    load_addr_to_reg(get_alloc_reg(dst_insn), insn->addr_val, insn->vr_type);
            } else if (insn->op == IR_INSN_STORERAW) {
                // storeraw
                if (insn->addr_val.value.type == IR_VALUE_STACK_PTR) {
                    // Store value in the stack
                    if (t0 == REG) {
                        extra->translated[0] =
                            store_reg_to_reg_mem(BPF_REG_10, get_alloc_reg(v0.data.insn_d),
                                                 insn->addr_val.offset, insn->vr_type);
                    } else if (t0 == CONST) {
                        extra->translated[0] = store_const_to_reg_mem(
                            BPF_REG_10, v0.data.constant_d, insn->addr_val.offset, insn->vr_type);
                    } else {
                        CRITICAL("Error");
                    }
                } else if (insn->addr_val.value.type == IR_VALUE_INSN) {
                    // Store value in (address in the value)
                    DBGASSERT(vtype(insn->addr_val.value) == REG);
                    // Store value in the stack
                    if (t0 == REG) {
                        extra->translated[0] = store_reg_to_reg_mem(
                            get_alloc_reg(insn->addr_val.value.data.insn_d),
                            get_alloc_reg(v0.data.insn_d), insn->addr_val.offset, insn->vr_type);
                    } else if (t0 == CONST) {
                        extra->translated[0] = store_const_to_reg_mem(
                            get_alloc_reg(insn->addr_val.value.data.insn_d), v0.data.constant_d,
                            insn->addr_val.offset, insn->vr_type);
                    } else {
                        CRITICAL("Error");
                    }
                } else {
                    CRITICAL("Error");
                }
            } else if (insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL) {
                DBGASSERT(tdst == REG);
                DBGASSERT(t0 == REG);
                DBGASSERT(get_alloc_reg(dst_insn) == get_alloc_reg(v0.data.insn_d));
                if (t1 == REG) {
                    extra->translated[0] =
                        alu_reg(get_alloc_reg(dst_insn), get_alloc_reg(v1.data.insn_d), insn->alu,
                                alu_code(insn->op));
                } else if (t1 == CONST) {
                    extra->translated[0] = alu_imm(get_alloc_reg(dst_insn), v1.data.constant_d,
                                                   insn->alu, alu_code(insn->op));
                } else {
                    CRITICAL("Error");
                }
            } else if (insn->op == IR_INSN_ASSIGN) {
            } else if (insn->op == IR_INSN_RET) {
                extra->translated[0].opcode = BPF_EXIT | BPF_JMP;
            } else if (insn->op == IR_INSN_CALL) {
                // Currently only support local helper functions
                extra->translated[0].opcode = BPF_CALL | BPF_JMP;
                extra->translated[0].it     = IMM;
                extra->translated[0].imm    = insn->fid;
            } else if (insn->op == IR_INSN_JA) {
                extra->translated[0].opcode = BPF_JMP | BPF_JA;
            } else if (insn->op >= IR_INSN_JEQ && insn->op < IR_INSN_PHI) {
            } else {
                CRITICAL("No such instruction");
            }
        }
    }
}
