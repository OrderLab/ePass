#ifndef __BPF_IR_CONSTRAINT_H__
#define __BPF_IR_CONSTRAINT_H__

#include "bpf_ir.h"

enum constraint_type {
    CONSTRAINT_TYPE_VALUE_EQUAL,
    CONSTRAINT_TYPE_VALUE_RANGE
};

struct ir_constraint {
    enum constraint_type type;

    // Range: [start, start + size)
    __u64 start;
    __u64 size;

    // Constrain value
    __u64 cval;

    // Real value to be compared
    struct ir_value val;
};

#endif
