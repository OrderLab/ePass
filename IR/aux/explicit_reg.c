// Make register usage explicit
// Example:
// %x = add %y, %arg1
// arg1 is r0 at the beginning of the function
// We then add a new instruction to the beginning of the function.

#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_insn.h"
#include "ir_helper.h"

void explicit_reg(struct ir_function *fun) {
    // fun is still in IR form
    struct ir_basic_block **pos;
    // Maximum number of functions: MAX_FUNC_ARG
    struct array call_insns                 = INIT_ARRAY(struct ir_insn *);
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            // struct ir_insn_cg_extra *extra = insn_cg(insn);
            if (insn->op == IR_INSN_CALL) {
                // Change the return value to NULL
                // The result is in r0
                // extra->dst = NULL;
                // struct ir_value val;
                // val.type        = IR_VALUE_INSN;
                // val.data.insn_d = &fun->cg_info.regs[0];
                // create_assign_insn(insn, val, INSERT_BACK);
                array_push(&call_insns, &insn);
            }
        }
    }
    for (__u8 i = 0; i < MAX_FUNC_ARG; ++i) {
        if (fun->function_arg[i]->users.num_elem > 0) {
            // Insert ASSIGN arg[i] at the beginning of the function
            struct ir_value val;
            val.type = IR_VALUE_INSN;
            val.data.insn_d = fun->cg_info.regs[i + 1];
            struct ir_insn *new_insn = create_assign_insn_bb_cg(fun->entry, val, INSERT_FRONT_AFTER_PHI);
            
            replace_all_usage(fun->function_arg[i], ir_value_insn(new_insn));
        }
    }
    array_free(&call_insns);
}

