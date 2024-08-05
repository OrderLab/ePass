#include "code_gen.h"
#include "eliminate_ssa.h"
#include "prog_check.h"

void code_gen(struct ir_function *fun){
    // Step 1: Check program
    prog_check(fun);
    // Step 2: Eliminate SSA
    elim_ssa(fun);
}