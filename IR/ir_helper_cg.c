#include <stdint.h>
#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "dbg.h"
#include "ir_insn.h"
#include "list.h"
#include "ir_helper.h"
#include "code_gen.h"

size_t get_dst_id(struct ir_insn *insn) {
    return ((struct ir_insn_cg_extra *)(insn->user_data))->dst->_insn_id;
}

void print_insn_ptr_cg(struct ir_insn *insn) {
    if (insn->_insn_id == SIZE_MAX) {
        printf("%p", insn);
        return;
    }
    printf("%%%zu", get_dst_id(insn));
}

void print_ir_value_cg(struct ir_value v) {
    if (v.type == IR_VALUE_INSN) {
        print_insn_ptr_cg(v.data.insn_d);
    } else {
        print_ir_value(v);
    }
}

void print_address_value_cg(struct ir_address_value v) {
    print_ir_value_cg(v.value);
    if (v.offset != 0) {
        printf("+%d", v.offset);
    }
}

void print_phi_cg(struct array *phi) {
    for (size_t i = 0; i < phi->num_elem; ++i) {
        struct phi_value v = ((struct phi_value *)(phi->data))[i];
        printf(" <");
        print_bb_ptr(v.bb);
        printf(" -> ");
        print_ir_value_cg(v.value);
        printf(">");
    }
}

/**
    Print the IR insn
 */
void print_ir_insn_cg(struct ir_insn *insn) {
    switch (insn->op) {
        case IR_INSN_ALLOC:
            printf("alloc ");
            print_vr_type(insn->vr_type);
            break;
        case IR_INSN_STORE:
            printf("store ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            break;
        case IR_INSN_LOAD:
            printf("load ");
            print_vr_type(insn->vr_type);
            printf(", ");
            print_ir_value_cg(insn->values[0]);
            break;
        case IR_INSN_LOADRAW:
            printf("loadraw ");
            print_vr_type(insn->vr_type);
            printf(" ");
            print_address_value_cg(insn->addr_val);
            break;
        case IR_INSN_STORERAW:
            printf("storeraw ");
            print_vr_type(insn->vr_type);
            printf(" ");
            print_address_value_cg(insn->addr_val);
            printf(" ");
            print_ir_value_cg(insn->values[0]);
            break;
        case IR_INSN_ADD:
            printf("add ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            break;
        case IR_INSN_SUB:
            printf("sub ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            break;
        case IR_INSN_MUL:
            printf("mul ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            break;
        case IR_INSN_CALL:
            printf("call __built_in_func_%d(", insn->fid);
            if (insn->value_num >= 1) {
                print_ir_value_cg(insn->values[0]);
            }
            for (size_t i = 1; i < insn->value_num; ++i) {
                printf(", ");
                print_ir_value_cg(insn->values[i]);
            }
            printf(")");
            break;
        case IR_INSN_RET:
            printf("ret ");
            print_ir_value_cg(insn->values[0]);
            break;
        case IR_INSN_JA:
            printf("ja ");
            print_bb_ptr(insn->bb1);
            break;
        case IR_INSN_JEQ:
            printf("jeq ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JGT:
            printf("jgt ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JGE:
            printf("jge ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JLT:
            printf("jlt ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JLE:
            printf("jle ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JNE:
            printf("jne ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_PHI:
            printf("phi");
            print_phi_cg(&insn->phi);
            break;
        case IR_INSN_LSH:
            printf("lsh ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            break;
        case IR_INSN_MOD:
            printf("mod ");
            print_ir_value_cg(insn->values[0]);
            printf(", ");
            print_ir_value_cg(insn->values[1]);
            break;
        case IR_INSN_ASSIGN:
            print_ir_value_cg(insn->values[0]);
            break;
        default:
            CRITICAL("Unknown IR insn");
    }
}

void print_ir_bb_cg(struct ir_basic_block *bb) {
    if (bb->_visited) {
        return;
    }
    bb->_visited = 1;
    printf("b%zu:\n", bb->_id);
    struct list_head *p = NULL;
    list_for_each(p, &bb->ir_insn_head) {
        struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
        if (is_void(insn)) {
            printf("  ");
        } else {
            printf("  %%%zu = ", get_dst_id(insn));
        }
        print_ir_insn_cg(insn);
        printf("\n");
    }
    for (size_t i = 0; i < bb->succs.num_elem; ++i) {
        struct ir_basic_block *next = ((struct ir_basic_block **)(bb->succs.data))[i];
        print_ir_bb_cg(next);
    }
}

void print_ir_prog_cg(struct ir_function *fun) {
    size_t cnt    = 0;
    size_t bb_cnt = 0;
    clean_env(fun);
    assign_id(fun->entry, &cnt, &bb_cnt);
    clean_env(fun);
    print_ir_bb_cg(fun->entry);
    clean_id(fun);
}
