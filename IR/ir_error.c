#include "ir_error.h"

struct error_code kernel_error(int x) {
    struct error_code ec;
    ec.code   = x;
    ec.ir_err = 0;
    if (x == 0) {
        ec.err = 0;
    } else {
        ec.err = 1;
    }
    return ec;
}

struct error_code ir_ok() {
    struct error_code ec;
    ec.err = 0;
    return ec;
}

struct error_code ir_error(enum ir_error x) {
    struct error_code ec;
    ec.code   = x;
    ec.ir_err = 1;
    ec.err    = 1;
    return ec;
}
