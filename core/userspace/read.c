// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include "linux/bpf_ir.h"
#include "userspace.h"
#include <stdio.h>

int main(int argn, char **argv)
{
	if (argn != 3) {
		return 1;
	}
	struct bpf_object *obj = bpf_object__open(argv[1]);
	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, argv[2]);
	if (!prog) {
		return 1;
	}
	size_t sz = bpf_program__insn_cnt(prog);
	const struct bpf_insn *insn = bpf_program__insns(prog);
	struct builtin_pass_cfg p1 = bpf_ir_kern_optimization_pass;
	p1.param_load("no_dead_elim", &p1.param);

	struct builtin_pass_cfg passes[] = { p1 };
	struct custom_pass_cfg custom_passes[] = {
		DEF_CUSTOM_PASS(DEF_FUNC_PASS(test_pass1, "test_pass1", true),
				NULL, NULL, NULL),
		// DEF_CUSTOM_PASS(DEF_FUNC_PASS(masking_pass, "masking", false),
		// 		NULL, NULL, NULL),
	};
	struct bpf_ir_opts opts = bpf_ir_default_opts();
	opts.custom_pass_num = 0;
	opts.custom_passes = custom_passes;
	opts.builtin_pass_cfg_num = 1;
	opts.builtin_pass_cfg = passes;
	opts.print_mode = BPF_IR_PRINT_BPF;
	struct bpf_ir_env *env = bpf_ir_init_env(opts, insn, sz);
	if (!env) {
		return 1;
	}
	bpf_ir_run(env);
	// bpf_ir_print_log_dbg(env);
	// To set the insns, you need to set the callback functions when loading
	// See https://github.com/libbpf/libbpf/blob/master/src/libbpf.h
	// bpf_program__set_insns(prog, env->insns, env->insn_cnt);
	bpf_ir_free_env(env);
	bpf_object__close(obj);
	p1.param_unload(p1.param);
}
