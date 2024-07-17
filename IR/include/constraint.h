#ifndef __BPF_IR_CONSTRAINT_H__
#define __BPF_IR_CONSTRAINT_H__

#include "bpf_ir.h"

enum constraint_type {
    CONSTRAINT_TYPE_VALUE_EQUAL,
    CONSTRAINT_TYPE_VALUE_RANGE
};

struct ir_constraint {
    enum constraint_type type;

    // Range: [start, end)
    struct ir_value start;
    struct ir_value end;

    // Constrain value
    struct ir_value cval;

    // Real value to be compared
    struct ir_value val;
    struct ir_insn *pos;
};

#endif
