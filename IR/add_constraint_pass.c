#include "add_constraint_pass.h"
#include "array.h"
#include "constraint.h"

// Initialize some testing constraints
void init_test_constraints(struct ir_function *fun) {
    fun->value_constraints = INIT_ARRAY(struct ir_constraint);
}

void add_constraint(struct ir_function *fun) {
    init_test_constraints(fun);
}
