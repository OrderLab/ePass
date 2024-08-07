#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_helper.h"

int compare_insn(const void *a, const void *b) {
    struct ir_insn *ap = *(struct ir_insn **)a;
    struct ir_insn *bp = *(struct ir_insn **)b;
    return ap->_insn_id > bp->_insn_id;
}

void graph_coloring(struct ir_function *fun) {
    // Using the Chaitin's Algorithm
    // Using the simple dominance heuristic (Simple traversal of BB)
    tag_ir(fun);
    struct array *all_var = &fun->cg_info.all_var;
    qsort(all_var->data, all_var->num_elem, all_var->elem_size, &compare_insn);
    // all_var is now PEO
    struct ir_insn **pos;
    array_for(pos, (*all_var)) {
        // Allocate register for *pos
        struct ir_insn          *insn  = *pos;
        struct ir_insn_cg_extra *extra = insn_cg(insn);
        struct ir_insn         **pos2;

        int          used_reg[__MAX_BPF_REG] = {0};
        struct array used_spill              = INIT_ARRAY(size_t);
        array_for(pos2, extra->adj) {
            struct ir_insn          *insn2  = *pos2;  // Adj instruction
            struct ir_insn_cg_extra *extra2 = insn_cg(insn2);
            if (extra2->allocated) {
                if (extra2->spilled) {
                    array_push_unique(&used_spill, &extra2->spilled);
                } else {
                    used_reg[extra2->alloc_reg] = 1;
                }
            }
        }
        __u8 need_spill = 1;
        for (__u8 i = 0; i < __MAX_BPF_REG; i++) {
            if (!used_reg[i]) {
                extra->allocated = 1;
                printf("Allocate r%u for %zu\n", i, insn->_insn_id);
                extra->alloc_reg = i;
                need_spill       = 0;
                break;
            }
        }
        if (need_spill) {
            size_t sp = 1;
            while (1) {
                __u8    found = 1;
                size_t *pos3;
                array_for(pos3, used_spill) {
                    if (*pos3 == sp) {
                        sp++;
                        found = 0;
                        break;
                    }
                }
                if (found) {
                    extra->allocated = 1;
                    extra->spilled   = sp;
                    break;
                }
            }
        }
        array_free(&used_spill);
    }
}
