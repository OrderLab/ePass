#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"

#define IU_REG0 BPF_REG_0
#define IU_REG1 BPF_REG_1

void save_to_reg(struct array *to_gen, __u8 reg, struct ir_value val) {
    // Save the full value to a register
}

void save_to_stack(struct array *to_gen, size_t offset, struct ir_value val) {}

void translate(struct ir_function *fun) {
    // fun is still in IR form
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *extra = insn_cg(insn);

            if (insn->op == IR_INSN_ALLOC) {
                // dst = alloc <size>
                // Nothing to do
            } else if (insn->op == IR_INSN_ASSIGN) {
                // dst = <val>
                // MOV dst val

            } else {
                CRITICAL("No such instruction");
            }
        }
    }
}