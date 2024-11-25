// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

// An optimization mentioned in MERLIN that is hard to do in LLVM

void bpf_ir_optimize_code_compaction(struct bpf_ir_env *env,
				     struct ir_function *fun, void *param)
{
}