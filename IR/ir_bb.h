#ifndef __BPF_IR_BB_H__
#define __BPF_IR_BB_H__

#include "bpf_ir.h"

/// Get the number of instructions in a basic block
size_t bb_len(struct ir_basic_block *);

#endif
