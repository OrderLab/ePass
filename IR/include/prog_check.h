#ifndef __BPF_IR_PROG_CHECK_H__
#define __BPF_IR_PROG_CHECK_H__

#include "ir_fun.h"

void prog_check(struct ir_function *fun);

void check_users(struct ir_function *fun);

void check_jumping(struct ir_function *fun);

#endif
