#include "eliminate_ssa.h"
#include "array.h"
#include "bpf_ir.h"

// Eliminate SSA Phi nodes
// Using "Method I" in paper "Translating Out of Static Single Assignment Form"
void elim_ssa(struct ir_function *fun){
    struct array phi_insns = INIT_ARRAY(struct ir_insn*);
    
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs){
        struct ir_basic_block *bb = *pos;
        struct ir_insn *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr){
            if (insn->op == IR_INSN_PHI) {
                array_push(&phi_insns, &insn);
            }else{
                break;
            }
        }
    }
}