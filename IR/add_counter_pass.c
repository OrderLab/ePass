#include "bpf_ir.h"

void add_counter(struct ir_function *fun) {
    struct ir_basic_block **pos;
    struct array           *arr = &fun->all_bbs;
    array_for(pos, arr) {
        print_raw_ir_bb(*pos);
    }
}
