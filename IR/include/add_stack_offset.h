#ifndef __BPF_IR_ADD_STACK_OFFSET_H__
#define __BPF_IR_ADD_STACK_OFFSET_H__

#include "ir_fun.h"

// Add stack offset to all stack access
void add_stack_offset(struct ir_function *fun, __s16 offset);

#endif
