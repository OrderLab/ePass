#include <stdio.h>
#include "bpf_ir.h"
#include "dbg.h"
#include "list.h"

/// Reset visited flag
void clean_env(struct ir_function *fun) {
    for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
        struct ir_basic_block *ir_bb = ((struct ir_basic_block **)(fun->all_bbs.data))[i];
        ir_bb->_visited              = 0;
    }
}

/// Reset instruction/BB ID
void clean_id(struct ir_function *fun) {
    for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
        struct ir_basic_block *ir_bb = ((struct ir_basic_block **)(fun->all_bbs.data))[i];
        ir_bb->_id                   = -1;
        struct list_head *p          = NULL;
        list_for_each(p, &ir_bb->ir_insn_head) {
            struct ir_insn *insn = list_entry(p, struct ir_insn, ptr);
            insn->_insn_id       = -1;
        }
    }
}

void print_constant(struct ir_constant d) {
    switch (d.type) {
        case IR_CONSTANT_S32:
            printf("%d", d.data.s32_d);
            break;
        case IR_CONSTANT_U32:
            printf("%u", d.data.u32_d);
            break;
        case IR_CONSTANT_U64:
            printf("%llu", d.data.u64_d);
            break;
        case IR_CONSTANT_S64:
            printf("%lld", d.data.s64_d);
            break;
        case IR_CONSTANT_S16:
            printf("%d", d.data.s16_d);
            break;
        case IR_CONSTANT_U16:
            printf("%u", d.data.u16_d);
            break;
        default:
            CRITICAL("Unknown constant type");
    }
}

void print_insn_ptr(struct ir_insn *insn) {
    printf("%%%zu", insn->_insn_id);
}

void print_ir_value(struct ir_value v) {
    switch (v.type) {
        case IR_VALUE_INSN:
            print_insn_ptr(v.data.insn_d);
            break;
        case IR_VALUE_STACK_PTR:
            printf("SP");
            break;
        case IR_VALUE_CONSTANT:
            print_constant(v.data.constant_d);
            break;
        case IR_VALUE_FUNCTIONARG:
            printf("arg%d", v.data.arg_id);
            break;
        default:
            CRITICAL("Unknown IR value type");
    }
}

void print_address_value(struct ir_address_value v) {
    print_ir_value(v.value);
    if (v.offset != 0) {
        printf("+%d", v.offset);
    }
}

void print_vr_type(enum ir_vr_type t) {
    switch (t) {
        case IR_VR_TYPE_U1:
            printf("u8");
            break;
        case IR_VR_TYPE_U8:
            printf("u64");
            break;
        case IR_VR_TYPE_U2:
            printf("u16");
            break;
        case IR_VR_TYPE_U4:
            printf("u32");
            break;
        case IR_VR_TYPE_S1:
            printf("s8");
            break;
        case IR_VR_TYPE_S2:
            printf("s16");
            break;
        case IR_VR_TYPE_S4:
            printf("s32");
            break;
        case IR_VR_TYPE_S8:
            printf("s64");
            break;
        case IR_VR_TYPE_PTR:
            printf("ptr");
            break;
        default:
            CRITICAL("Unknown VR type");
    }
}

void print_phi(struct array *phi) {
    for (size_t i = 0; i < phi->num_elem; ++i) {
        struct phi_value v = ((struct phi_value *)(phi->data))[i];
        printf(" <");
        printf("b%zu -> ", v.bb->_id);
        print_ir_value(v.value);
        printf(">");
    }
}

/**
    Print the IR insn
 */
void print_ir_insn(struct ir_insn *insn) {
    switch (insn->op) {
        case IR_INSN_ALLOC:
            printf("alloc ");
            print_vr_type(insn->vr_type);
            break;
        case IR_INSN_STORE:
            // TODO
            printf("store");
            break;
        case IR_INSN_LOAD:
            // TODO
            printf("load");
            break;
        case IR_INSN_LOADRAW:
            printf("loadraw ");
            print_vr_type(insn->vr_type);
            printf(" ");
            print_address_value(insn->addr_val);
            break;
        case IR_INSN_STORERAW:
            printf("storeraw ");
            print_vr_type(insn->vr_type);
            printf(" ");
            print_address_value(insn->addr_val);
            printf(" ");
            print_ir_value(insn->v1);
            break;
        case IR_INSN_ADD:
            printf("add ");
            print_ir_value(insn->v1);
            printf(", ");
            print_ir_value(insn->v2);
            break;
        case IR_INSN_SUB:
            printf("sub ");
            print_ir_value(insn->v1);
            printf(", ");
            print_ir_value(insn->v2);
            break;
        case IR_INSN_MUL:
            printf("mul ");
            print_ir_value(insn->v1);
            printf(", ");
            print_ir_value(insn->v2);
            break;
        case IR_INSN_CALL:
            printf("call __built_in_func_%d(", insn->fid);
            if (insn->f_arg_num >= 1) {
                print_ir_value(insn->v1);
            }
            if (insn->f_arg_num >= 2) {
                printf(", ");
                print_ir_value(insn->v2);
            }
            if (insn->f_arg_num >= 3) {
                printf(", ");
                print_ir_value(insn->v3);
            }
            if (insn->f_arg_num >= 4) {
                printf(", ");
                print_ir_value(insn->v4);
            }
            printf(")");
            break;
        case IR_INSN_RET:
            printf("ret ");
            print_ir_value(insn->v1);
            break;
        case IR_INSN_JA:
            printf("ja b%zu", insn->bb->_id);
            break;
        case IR_INSN_JEQ:
            printf("jeq ");
            print_ir_value(insn->v1);
            printf(", ");
            print_ir_value(insn->v2);
            printf(", b%zu", insn->bb->_id);
            break;
        case IR_INSN_JGT:
            printf("jgt ");
            print_ir_value(insn->v1);
            printf(", ");
            print_ir_value(insn->v2);
            printf(", b%zu", insn->bb->_id);
            break;
        case IR_INSN_JGE:
            printf("jge ");
            print_ir_value(insn->v1);
            printf(", ");
            print_ir_value(insn->v2);
            printf(", b%zu", insn->bb->_id);
            break;
        case IR_INSN_JLT:
            printf("jlt ");
            print_ir_value(insn->v1);
            printf(", ");
            print_ir_value(insn->v2);
            printf(", b%zu", insn->bb->_id);
            break;
        case IR_INSN_JLE:
            printf("jle ");
            print_ir_value(insn->v1);
            printf(", ");
            print_ir_value(insn->v2);
            printf(", b%zu", insn->bb->_id);
            break;
        case IR_INSN_JNE:
            printf("jne ");
            print_ir_value(insn->v1);
            printf(", ");
            print_ir_value(insn->v2);
            printf(", b%zu", insn->bb->_id);
            break;
        case IR_INSN_PHI:
            printf("phi ");
            print_phi(&insn->phi);
            break;
        default:
            CRITICAL("Unknown IR insn");
    }
}

void print_ir_bb(struct ir_basic_block *bb) {
    if (bb->_visited) {
        return;
    }
    bb->_visited = 1;
    printf("b%zu:\n", bb->_id);
    struct list_head *p = NULL;
    list_for_each(p, &bb->ir_insn_head) {
        struct ir_insn *insn = list_entry(p, struct ir_insn, ptr);
        printf("  %%%zu = ", insn->_insn_id);
        print_ir_insn(insn);
        printf("\n");
    }
    for (size_t i = 0; i < bb->succs.num_elem; ++i) {
        struct ir_basic_block *next = ((struct ir_basic_block **)(bb->succs.data))[i];
        print_ir_bb(next);
    }
}

void assign_id(struct ir_basic_block *bb, size_t *cnt, size_t *bb_cnt) {
    if (bb->_visited) {
        return;
    }
    bb->_visited        = 1;
    bb->_id             = (*bb_cnt)++;
    struct list_head *p = NULL;
    list_for_each(p, &bb->ir_insn_head) {
        struct ir_insn *insn = list_entry(p, struct ir_insn, ptr);
        insn->_insn_id       = (*cnt)++;
    }
    for (size_t i = 0; i < bb->succs.num_elem; ++i) {
        struct ir_basic_block *next = ((struct ir_basic_block **)(bb->succs.data))[i];
        assign_id(next, cnt, bb_cnt);
    }
}

void print_ir_prog(struct ir_function *fun) {
    size_t cnt    = 0;
    size_t bb_cnt = 0;
    clean_env(fun);
    assign_id(fun->entry, &cnt, &bb_cnt);
    clean_env(fun);
    print_ir_bb(fun->entry);
    clean_id(fun);
}
