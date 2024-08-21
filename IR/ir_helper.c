#include <stdint.h>
#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_insn.h"
#include "list.h"
#include "ir_fun.h"

/// Reset visited flag
void clean_env_all(struct ir_function *fun) {
    for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
        struct ir_basic_block *bb = ((struct ir_basic_block **)(fun->all_bbs.data))[i];
        bb->_visited              = 0;
        bb->user_data             = NULL;
        struct list_head *p       = NULL;
        list_for_each(p, &bb->ir_insn_head) {
            struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
            insn->user_data      = NULL;
            insn->_visited       = 0;
        }
    }
}

void clean_env(struct ir_function *fun) {
    for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
        struct ir_basic_block *bb = ((struct ir_basic_block **)(fun->all_bbs.data))[i];
        bb->_visited              = 0;
        struct list_head *p       = NULL;
        list_for_each(p, &bb->ir_insn_head) {
            struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
            insn->_visited       = 0;
        }
    }
}

/// Reset instruction/BB ID
void clean_tag(struct ir_function *fun) {
    for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
        struct ir_basic_block *ir_bb = ((struct ir_basic_block **)(fun->all_bbs.data))[i];
        ir_bb->_id                   = -1;
        struct list_head *p          = NULL;
        list_for_each(p, &ir_bb->ir_insn_head) {
            struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
            insn->_insn_id       = -1;
        }
    }
}

void print_constant(struct ir_constant d) {
    switch (d.type) {
        case IR_CONSTANT_S32:
            if (d.data.s32_d < 0) {
                printf("-0x%x", -d.data.s32_d);
            } else {
                printf("0x%x", d.data.s32_d);
            }
            break;
        case IR_CONSTANT_U32:
            printf("0x%x", d.data.u32_d);
            break;
        case IR_CONSTANT_U64:
            printf("0x%llx", d.data.u64_d);
            break;
        case IR_CONSTANT_S64:
            if (d.data.s64_d < 0) {
                printf("-0x%llx", -d.data.s64_d);
            } else {
                printf("0x%llx", d.data.s64_d);
            }
            break;
        case IR_CONSTANT_S16:
            if (d.data.s16_d < 0) {
                printf("-0x%x", -d.data.s16_d);
            } else {
                printf("0x%x", d.data.s16_d);
            }
            break;
        case IR_CONSTANT_U16:
            printf("0x%x", d.data.u16_d);
            break;
        default:
            CRITICAL("Unknown constant type");
    }
}

void print_insn_ptr_base(struct ir_insn *insn) {
    if (insn->op == IR_INSN_REG) {
        printf("R%u", insn_cg(insn)->alloc_reg);
        return;
    }
    if (insn->op == IR_INSN_FUNCTIONARG) {
        printf("arg%u", insn->fid);
        return;
    }
    if (insn->_insn_id == SIZE_MAX) {
        printf("%p", insn);
        return;
    }
    printf("%%%zu", insn->_insn_id);
}

void print_insn_ptr(struct ir_insn *insn, void (*print_ir)(struct ir_insn *)) {
    if (print_ir) {
        print_ir(insn);
    } else {
        print_insn_ptr_base(insn);
    }
}

void print_bb_ptr(struct ir_basic_block *insn) {
    if (insn->_id == SIZE_MAX) {
        printf("b%p", insn);
        return;
    }
    printf("b%zu", insn->_id);
}

void print_ir_value_full(struct ir_value v, void (*print_ir)(struct ir_insn *)) {
    switch (v.type) {
        case IR_VALUE_INSN:
            print_insn_ptr(v.data.insn_d, print_ir);
            break;
        case IR_VALUE_STACK_PTR:
            printf("SP");
            break;
        case IR_VALUE_CONSTANT:
            print_constant(v.data.constant_d);
            break;
        case IR_VALUE_UNDEF:
            printf("undef");
            break;
        default:
            CRITICAL("Unknown IR value type");
    }
}

void print_ir_value(struct ir_value v) {
    print_ir_value_full(v, 0);
}

void print_address_value_full(struct ir_address_value v, void (*print_ir)(struct ir_insn *)) {
    print_ir_value_full(v.value, print_ir);
    if (v.offset != 0) {
        printf("+%d", v.offset);
    }
}

void print_address_value(struct ir_address_value v) {
    print_address_value_full(v, 0);
}

void print_vr_type(enum ir_vr_type t) {
    switch (t) {
        case IR_VR_TYPE_8:
            printf("u8");
            break;
        case IR_VR_TYPE_64:
            printf("u64");
            break;
        case IR_VR_TYPE_16:
            printf("u16");
            break;
        case IR_VR_TYPE_32:
            printf("u32");
            break;
        default:
            CRITICAL("Unknown VR type");
    }
}

void print_phi_full(struct array *phi, void (*print_ir)(struct ir_insn *)) {
    for (size_t i = 0; i < phi->num_elem; ++i) {
        struct phi_value v = ((struct phi_value *)(phi->data))[i];
        printf(" <");
        print_bb_ptr(v.bb);
        printf(" -> ");
        print_ir_value_full(v.value, print_ir);
        printf(">");
    }
}

void print_phi(struct array *phi) {
    print_phi_full(phi, 0);
}

/**
    Print the IR insn
 */
void print_ir_insn_full(struct ir_insn *insn, void (*print_ir)(struct ir_insn *)) {
    switch (insn->op) {
        case IR_INSN_ALLOC:
            printf("alloc ");
            print_vr_type(insn->vr_type);
            break;
        case IR_INSN_STORE:
            printf("store ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            break;
        case IR_INSN_LOAD:
            printf("load ");
            print_vr_type(insn->vr_type);
            printf(", ");
            print_ir_value_full(insn->values[0], print_ir);
            break;
        case IR_INSN_LOADRAW:
            printf("loadraw ");
            print_vr_type(insn->vr_type);
            printf(" ");
            print_address_value_full(insn->addr_val, print_ir);
            break;
        case IR_INSN_STORERAW:
            printf("storeraw ");
            print_vr_type(insn->vr_type);
            printf(" ");
            print_address_value_full(insn->addr_val, print_ir);
            printf(" ");
            print_ir_value_full(insn->values[0], print_ir);
            break;
        case IR_INSN_ADD:
            printf("add ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            break;
        case IR_INSN_SUB:
            printf("sub ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            break;
        case IR_INSN_MUL:
            printf("mul ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            break;
        case IR_INSN_CALL:
            printf("call __built_in_func_%d(", insn->fid);
            if (insn->value_num >= 1) {
                print_ir_value_full(insn->values[0], print_ir);
            }
            for (size_t i = 1; i < insn->value_num; ++i) {
                printf(", ");
                print_ir_value_full(insn->values[i], print_ir);
            }
            printf(")");
            break;
        case IR_INSN_RET:
            printf("ret ");
            if (insn->value_num > 0) {
                print_ir_value_full(insn->values[0], print_ir);
            }
            break;
        case IR_INSN_JA:
            printf("ja ");
            print_bb_ptr(insn->bb1);
            break;
        case IR_INSN_JEQ:
            printf("jeq ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JGT:
            printf("jgt ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JGE:
            printf("jge ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JLT:
            printf("jlt ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JLE:
            printf("jle ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_JNE:
            printf("jne ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            printf(", ");
            print_bb_ptr(insn->bb1);
            printf("/");
            print_bb_ptr(insn->bb2);
            break;
        case IR_INSN_PHI:
            printf("phi");
            print_phi_full(&insn->phi, print_ir);
            break;
        case IR_INSN_LSH:
            printf("lsh ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            break;
        case IR_INSN_MOD:
            printf("mod ");
            print_ir_value_full(insn->values[0], print_ir);
            printf(", ");
            print_ir_value_full(insn->values[1], print_ir);
            break;
        case IR_INSN_ASSIGN:
            print_ir_value_full(insn->values[0], print_ir);
            break;
        default:
            CRITICAL("Unknown IR insn");
    }
}

void print_ir_insn(struct ir_insn *insn) {
    print_ir_insn_full(insn, 0);
}

void print_raw_ir_insn_full(struct ir_insn *insn, void (*print_ir)(struct ir_insn *)) {
    if (print_ir) {
        print_ir(insn);
    } else {
        printf("%p", insn);
    }
    printf(" = ");
    print_ir_insn_full(insn, print_ir);
    printf("\n");
}

void print_raw_ir_insn(struct ir_insn *insn) {
    print_raw_ir_insn_full(insn, 0);
}

void print_ir_bb(struct ir_basic_block *bb, void (*post_bb)(struct ir_basic_block *),
                 void (*post_insn)(struct ir_insn *), void (*print_insn_name)(struct ir_insn *)) {
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
            printf("  ");
            if (print_insn_name) {
                print_insn_name(insn);
            } else {
                printf("%%%zu", insn->_insn_id);
            }
            printf(" = ");
        }

        print_ir_insn_full(insn, print_insn_name);
        printf("\n");
        if (post_insn) {
            post_insn(insn);
        }
    }
    if (post_bb) {
        post_bb(bb);
    }
    for (size_t i = 0; i < bb->succs.num_elem; ++i) {
        struct ir_basic_block *next = ((struct ir_basic_block **)(bb->succs.data))[i];
        print_ir_bb(next, post_bb, post_insn, print_insn_name);
    }
}

void print_raw_ir_bb_full(struct ir_basic_block *bb, void (*print_ir)(struct ir_insn *)) {
    printf("b%p:\n", bb);
    struct list_head *p = NULL;
    list_for_each(p, &bb->ir_insn_head) {
        struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
        printf("  ");
        print_raw_ir_insn_full(insn, print_ir);
    }
}

void print_raw_ir_bb(struct ir_basic_block *bb) {
    print_raw_ir_bb_full(bb, 0);
}

void assign_id(struct ir_basic_block *bb, size_t *cnt, size_t *bb_cnt) {
    if (bb->_visited) {
        return;
    }
    bb->_visited        = 1;
    bb->_id             = (*bb_cnt)++;
    struct list_head *p = NULL;
    list_for_each(p, &bb->ir_insn_head) {
        struct ir_insn *insn = list_entry(p, struct ir_insn, list_ptr);
        if (!is_void(insn)) {
            insn->_insn_id = (*cnt)++;
        }
    }
    struct ir_basic_block **next;
    array_for(next, bb->succs) {
        assign_id(*next, cnt, bb_cnt);
    }
}

void tag_ir(struct ir_function *fun) {
    size_t cnt    = 0;
    size_t bb_cnt = 0;
    clean_env(fun);
    assign_id(fun->entry, &cnt, &bb_cnt);
    clean_env(fun);
}

void print_bb_succ(struct ir_basic_block *bb) {
    printf("succs: ");
    struct ir_basic_block **next;
    array_for(next, bb->succs) {
        print_bb_ptr(*next);
        printf(" ");
    }
    printf("\n\n");
}

void print_ir_prog(struct ir_function *fun) {
    tag_ir(fun);
    print_ir_bb(fun->entry, NULL, NULL, NULL);
    clean_tag(fun);
}

void print_ir_dst(struct ir_insn *insn) {
    insn = dst(insn);
    if (insn) {
        print_insn_ptr_base(insn);
    } else {
        printf("(NULL)");
    }
}

void print_ir_alloc(struct ir_insn *insn) {
    insn = dst(insn);
    if (insn) {
        struct ir_insn_cg_extra *extra = insn_cg(insn);
        if (extra->allocated) {
            if (extra->spilled) {
                printf("sp-%zu", extra->spilled * 8);
            } else {
                printf("r%u", extra->alloc_reg);
            }
        } else {
            CRITICAL("Not allocated");
        }
    } else {
        printf("(NULL)");
    }
}

void print_ir_prog_advanced(struct ir_function *fun, void (*post_bb)(struct ir_basic_block *),
                            void (*post_insn)(struct ir_insn *),
                            void (*print_insn_name)(struct ir_insn *)) {
    tag_ir(fun);
    print_ir_bb(fun->entry, post_bb, post_insn, print_insn_name);
    clean_tag(fun);
}
