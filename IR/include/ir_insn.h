#ifndef __BPF_IR_INSN_H__
#define __BPF_IR_INSN_H__

#include "bpf_ir.h"

enum insert_position {
    INSERT_BACK,
    INSERT_FRONT,
};

void create_undef_insn(struct ir_insn *insn, enum insert_position pos);

void create_alloc_insn_bb(struct ir_basic_block *bb, enum ir_vr_type type,
                          enum insert_position pos);
#endif
