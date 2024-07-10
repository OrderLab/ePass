#include "bpf_ir.h"

void add_counter(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        print_raw_ir_bb(*pos);
    }
}
