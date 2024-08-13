// Live variable analysis
#include <stdio.h>
#include <time.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_bb.h"
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
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *pos2;
        // For each operation
        list_for_each_entry(pos2, &bb->ir_insn_head, list_ptr) {
            struct ir_insn          *insn_dst = dst(pos2);
            struct ir_insn_cg_extra *insn_cg  = pos2->user_data;
            if (!is_void(pos2) && insn_dst) {
                array_push_unique(&insn_cg->kill, &insn_dst);
            }
            struct array      value_uses = get_operands(pos2);
            struct ir_value **pos3;
            array_for(pos3, value_uses) {
                struct ir_value *val = *pos3;
                if (val->type == IR_VALUE_INSN) {
                    struct ir_insn *insn = dst(val->data.insn_d);
                    array_push_unique(&insn_cg->gen, &insn);
                    // array_erase_elem(&insn_cg->kill, insn);
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
            struct ir_basic_block *bb = *pos;
            struct ir_insn        *insn;

            list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
                struct ir_insn_cg_extra *insn_cg = insn->user_data;
                struct array             old_in  = insn_cg->in;
                array_clear(&insn_cg->out);

                if (get_last_insn(bb) == insn) {
                    // Last instruction
                    struct ir_basic_block **pos2;
                    array_for(pos2, bb->succs) {
                        struct ir_basic_block *bb2 = *pos2;
                        if (bb_empty(bb2)) {
                            CRITICAL("Found empty BB");
                        }
                        struct ir_insn          *first    = get_first_insn(bb2);
                        struct ir_insn_cg_extra *insn2_cg = first->user_data;
                        merge_array(&insn_cg->out, &insn2_cg->in);
                    }
                } else {
                    // Not last instruction
                    struct ir_insn *next_insn =
                        list_entry(insn->list_ptr.next, struct ir_insn, list_ptr);
                    struct ir_insn_cg_extra *next_insn_cg = next_insn->user_data;
                    merge_array(&insn_cg->out, &next_insn_cg->in);
                }
                struct array out_kill_delta = array_delta(&insn_cg->out, &insn_cg->kill);
                insn_cg->in                 = array_clone(&insn_cg->gen);
                merge_array(&insn_cg->in, &out_kill_delta);
                // Check for change
                if (!equal_set(&insn_cg->in, &old_in)) {
                    change = 1;
                }
                // Collect grabage
                array_free(&out_kill_delta);
                array_free(&old_in);
            }
        }
    }
}

void print_insn_extra(struct ir_insn *insn) {
    struct ir_insn_cg_extra *insn_cg = insn->user_data;
    if (insn_cg == NULL) {
        CRITICAL("NULL user data");
    }
    printf("--\nGen:");
    struct ir_insn **pos;
    array_for(pos, insn_cg->gen) {
        struct ir_insn *insn = *pos;
        printf(" %%%zu", insn->_insn_id);
    }
    printf("\nKill:");
    array_for(pos, insn_cg->kill) {
        struct ir_insn *insn = *pos;
        printf(" %%%zu", insn->_insn_id);
    }
    printf("\nIn:");
    array_for(pos, insn_cg->in) {
        struct ir_insn *insn = *pos;
        printf(" %%%zu", insn->_insn_id);
    }
    printf("\nOut:");
    array_for(pos, insn_cg->out) {
        struct ir_insn *insn = *pos;
        printf(" %%%zu", insn->_insn_id);
    }
    printf("\n-------------\n");
}

void liveness_analysis(struct ir_function *fun) {
    // TODO: Encode Calling convention into GEN KILL
    gen_kill(fun);
    in_out(fun);
    printf("--------------\n");
    print_ir_prog_advanced(fun, NULL, print_insn_extra, print_ir_dst);
    print_ir_prog_advanced(fun, NULL, NULL, print_ir_dst);
}
