// Live variable analysis
#include <stdio.h>
#include <time.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_fun.h"
#include "ir_insn.h"
#include "list.h"
#include "ir_helper.h"

void array_erase_elem(struct array *arr, struct ir_insn *insn) {
    // Remove insn from arr
    for (size_t i = 0; i < arr->num_elem; ++i) {
        struct ir_insn *pos = ((struct ir_insn **)(arr->data))[i];
        if (pos == insn) {
            array_erase(arr, i);
            return;
        }
    }
}

void gen_kill(struct ir_function *fun) {
    struct ir_basic_block **pos;
    // For each BB
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = bb->user_data;
        struct ir_insn        *pos2;
        // For each operation in reverse
        list_for_each_entry_reverse(pos2, &bb->ir_insn_head, list_ptr) {
            struct ir_insn *insn_dst = dst(pos2);
            if (!is_void(pos2)) {
                array_erase_elem(&bb_cg->gen, insn_dst);
                array_push_unique(&bb_cg->kill, &insn_dst);
            }
            struct array      value_uses = get_operands(pos2);
            struct ir_value **pos3;
            array_for(pos3, value_uses) {
                struct ir_value *val = *pos3;
                if (val->type == IR_VALUE_INSN) {
                    struct ir_insn *insn = dst(val->data.insn_d);
                    array_push_unique(&bb_cg->gen, &insn);
                    array_erase_elem(&bb_cg->kill, insn);
                }
            }
        }
    }
}

int array_contains(struct array *arr, struct ir_insn *insn) {
    struct ir_insn **pos;
    array_for(pos, (*arr)) {
        if (*pos == insn) {
            return 1;
        }
    }
    return 0;
}

struct array array_delta(struct array *a, struct array *b) {
    struct array     res = INIT_ARRAY(struct ir_insn *);
    struct ir_insn **pos;
    array_for(pos, (*a)) {
        struct ir_insn *insn = *pos;
        if (!array_contains(b, insn)) {
            array_push(&res, &insn);
        }
    }
    return res;
}

void merge_array(struct array *a, struct array *b) {
    struct ir_insn **pos;
    array_for(pos, (*b)) {
        struct ir_insn *insn = *pos;
        array_push_unique(a, &insn);
    }
}

int equal_set(struct array *a, struct array *b) {
    if (a->num_elem != b->num_elem) {
        return 0;
    }
    struct ir_insn **pos;
    array_for(pos, (*a)) {
        struct ir_insn *insn = *pos;
        if (!array_contains(b, insn)) {
            return 0;
        }
    }
    return 1;
}

void in_out(struct ir_function *fun) {
    int change = 1;
    // For each BB
    while (change) {
        change = 0;
        struct ir_basic_block **pos;
        array_for(pos, fun->reachable_bbs) {
            struct ir_basic_block  *bb     = *pos;
            struct ir_bb_cg_extra  *bb_cg  = bb->user_data;
            struct array            old_in = bb_cg->in;
            struct ir_basic_block **pos2;
            array_clear(&bb_cg->out);
            array_for(pos2, bb->succs) {
                struct ir_bb_cg_extra *bb_cg2 = (*pos2)->user_data;
                merge_array(&bb_cg->out, &bb_cg2->in);
            }
            struct array out_kill_delta = array_delta(&bb_cg->out, &bb_cg->kill);
            bb_cg->in                   = array_clone(&bb_cg->gen);
            merge_array(&bb_cg->in, &out_kill_delta);
            // Check for change
            if (!equal_set(&bb_cg->in, &old_in)) {
                change = 1;
            }
            // Collect grabage
            array_free(&out_kill_delta);
            array_free(&old_in);
        }
    }
}

void print_bb_extra(struct ir_basic_block *bb) {
    struct ir_bb_cg_extra *bb_cg = bb->user_data;
    if (bb->user_data == NULL) {
        CRITICAL("NULL user data");
    }
    printf("--\nGen:");
    struct ir_insn **pos;
    array_for(pos, bb_cg->gen) {
        struct ir_insn *insn = *pos;
        printf(" %%%zu", insn->_insn_id);
    }
    printf("\nKill:");
    array_for(pos, bb_cg->kill) {
        struct ir_insn *insn = *pos;
        printf(" %%%zu", insn->_insn_id);
    }
    printf("\nIn:");
    array_for(pos, bb_cg->in) {
        struct ir_insn *insn = *pos;
        printf(" %%%zu", insn->_insn_id);
    }
    printf("\nOut:");
    array_for(pos, bb_cg->out) {
        struct ir_insn *insn = *pos;
        printf(" %%%zu", insn->_insn_id);
    }
    printf("\n-------------\n");
}

void liveness_analysis(struct ir_function *fun) {
    gen_kill(fun);
    in_out(fun);
    printf("--------------\n");
    print_ir_prog_advanced(fun, print_bb_extra, 1);
}
