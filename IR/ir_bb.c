#include "ir_bb.h"
#include "bpf_ir.h"

size_t bb_len(struct ir_basic_block *bb) {
    size_t            len = 0;
    struct list_head *p   = NULL;
    list_for_each(p, &bb->ir_insn_head) {
        len++;
    }
    return len;
}
