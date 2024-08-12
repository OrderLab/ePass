#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"

void translate(struct ir_function *fun) {
    // fun is still in IR form
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *extra = insn_cg(insn);

            struct pre_ir_insn *translated1 = &extra->translated[0];
            struct pre_ir_insn *translated2 = &extra->translated[1];

            if (insn->op == IR_INSN_ALLOC) {
                // alloc <size>
            } else {
                CRITICAL("No such instruction");
            }
        }
    }
}