// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include "epasstool.h"

int read(struct user_opts uopts)
{
	struct bpf_object *obj = bpf_object__open(uopts.prog);
	if (!obj) {
		printf("Failed to open object\n");
		return 1;
	}
	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, uopts.sec);

	if (!prog) {
		printf("Program not found\n");
		return 1;
	}
	size_t sz = bpf_program__insn_cnt(prog);
	const struct bpf_insn *insn = bpf_program__insns(prog);
	struct bpf_ir_env *env = bpf_ir_init_env(uopts.opts, insn, sz);
	if (!env) {
		return 1;
	}
	int err = bpf_ir_init_opts(env, uopts.gopt, uopts.popt);
	if (err) {
		return err;
	}
	enable_builtin(env);
	bpf_ir_autorun(env);

	if (env->err) {
		return env->err;
	}

	bpf_ir_free_opts(env);
	bpf_ir_free_env(env);
	bpf_object__close(obj);
	return 0;
}
