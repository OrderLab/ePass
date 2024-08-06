#ifndef __BPF_IR_HELPER_H__
#define __BPF_IR_HELPER_H__

#include "ir_fun.h"

void clean_env_all(struct ir_function *fun);

void print_ir_prog(struct ir_function *);

void print_ir_prog_advanced(struct ir_function *fun, void (*post_fun)(struct ir_basic_block *),
                            int);

void clean_env(struct ir_function *);

void clean_env_all(struct ir_function *fun);

// Tag the instruction and BB
void tag_ir(struct ir_function *fun);

// Remove all tag information
void clean_tag(struct ir_function *);

void print_constant(struct ir_constant d);

void print_address_value(struct ir_address_value v);

void print_vr_type(enum ir_vr_type t);

void print_phi(struct array *phi);

void assign_id(struct ir_basic_block *bb, size_t *cnt, size_t *bb_cnt);

void print_ir_insn(struct ir_insn *);

void print_ir_value(struct ir_value v);

void print_raw_ir_insn(struct ir_insn *insn);

void print_raw_ir_bb(struct ir_basic_block *bb);

#endif
