#include <linux/bpf.h>
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

struct pre_ir_insn load_const_to_reg(enum ir_constant_type ty, __u8 src) {
    // MOV dst imm
    struct pre_ir_insn insn;
    // TODO
    return insn;
}

struct pre_ir_insn load_addr_to_reg(__u8 dst, __u8 src) {
    // MOV dst src
    struct pre_ir_insn insn;
    insn.opcode  = BPF_MOV | BPF_X | BPF_ALU64;
    insn.dst_reg = dst;
    insn.src_reg = src;
    return insn;
}

void translate(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_value v0 = insn->values[0];
            struct ir_value v1 = insn->values[1];
            if (insn->op == IR_INSN_ALLOC) {
                // dst = alloc <size>
                // Nothing to do
            } else if (insn->op == IR_INSN_STORE) {
                if (vtype(v0) == STACK && vtype(v1) == REG) {
                } else {
                    CRITICAL("Not applicable");
                }
            } else if (insn->op == IR_INSN_LOAD) {
                // OK
            } else if (insn->op == IR_INSN_LOADRAW) {
                // OK
            } else if (insn->op == IR_INSN_STORERAW) {
            } else if (insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL) {
            } else if (insn->op == IR_INSN_ASSIGN) {
                // dst = <val>
                // MOV dst val

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
