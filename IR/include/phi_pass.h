#ifndef __BPF_IR_PHI_PASS_H__
#define __BPF_IR_PHI_PASS_H__

#include "ir_fun.h"

void remove_trivial_phi(struct ir_function *fun);

#endif
