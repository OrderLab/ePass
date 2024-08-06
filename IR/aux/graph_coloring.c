#include <stdlib.h>
#include "bpf_ir.h"
#include "code_gen.h"
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
}