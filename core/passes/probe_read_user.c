// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

// https://stackoverflow.com/questions/77762365/ebpf-value-is-outside-of-the-allowed-memory-range-when-reading-data-into-arra

void bpf_ir_probe_read_user_check(struct bpf_ir_env *env,
				     struct ir_function *fun, void *param)
{
    
}