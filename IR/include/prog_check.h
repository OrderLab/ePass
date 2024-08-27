#ifndef __BPF_IR_PROG_CHECK_H__
#define __BPF_IR_PROG_CHECK_H__

#include "ir_fun.h"

void check_jumping(struct ir_function *fun);

void cg_prog_check(struct ir_function *fun);

#endif
