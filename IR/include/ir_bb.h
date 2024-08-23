#ifndef __BPF_IR_BB_H__
#define __BPF_IR_BB_H__

#include "bpf_ir.h"
#include "ir_fun.h"

/// Get the number of instructions in a basic block
size_t bb_len(struct ir_basic_block *);

struct ir_bb_cg_extra *bb_cg(struct ir_basic_block *bb);

struct ir_basic_block *create_bb(struct ir_function *fun);

void connect_bb(struct ir_basic_block *from, struct ir_basic_block *to);

void disconnect_bb(struct ir_basic_block *from, struct ir_basic_block *to);

/// Split a BB after an instruction
struct ir_basic_block *split_bb(struct ir_function *fun, struct ir_insn *insn);

struct ir_insn *get_last_insn(struct ir_basic_block *bb);

struct ir_insn *get_first_insn(struct ir_basic_block *bb);

int bb_empty(struct ir_basic_block *bb);

#endif
