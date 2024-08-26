#ifndef __BPF_IR_ERROR_H__
#define __BPF_IR_ERROR_H__
#include "bpf_ir.h"

enum ir_error {
    IR_ERROR_SYNTAX
};

struct error_code {
    // Whether the function returns an error code
    __u8 err : 1;

    // Whether the error code is a kernel error code
    __u8 ir_err : 1;

    // The error code
    int code : 30;
};

struct error_code kernel_error(int x);

struct error_code ir_ok();

struct error_code ir_error(enum ir_error x);

#endif
