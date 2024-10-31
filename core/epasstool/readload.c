// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include "epasstool.h"

static struct bpf_ir_env *env;

static int callback_fn(struct bpf_program *prog,
		       struct bpf_prog_load_opts *opts, long cookie)
{
	if (!env->err) {
		bpf_program__set_insns(prog, env->insns, env->insn_cnt);
		printf("New program size: %zu\n", bpf_program__insn_cnt(prog));
		return 0;
	} else {
		return -1;
	}
}

int readload(struct user_opts uopts)
{
	struct bpf_object *obj = bpf_object__open(uopts.prog);
	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, uopts.sec);
	if (!prog) {
		return 1;
	}
	size_t sz = bpf_program__insn_cnt(prog);
	const struct bpf_insn *insn = bpf_program__insns(prog);
	env = bpf_ir_init_env(uopts.opts, insn, sz);
	if (!env) {
		return 1;
	}
	int err = bpf_ir_init_opts(env, uopts.gopt, uopts.popt);
	if (err) {
		return err;
	}
	enable_builtin(env);
	bpf_ir_run(env);

	struct libbpf_prog_handler_opts handler_opts;
	handler_opts.sz = sizeof(handler_opts);
	handler_opts.prog_attach_fn = NULL;
	handler_opts.prog_setup_fn = NULL;
	handler_opts.prog_prepare_load_fn = callback_fn;
	libbpf_register_prog_handler(bpf_program__section_name(prog),
				     bpf_program__get_type(prog),
				     bpf_program__expected_attach_type(prog),
				     &handler_opts);
	bpf_object__close(obj);
	obj = bpf_object__open(uopts.prog);
	bpf_object__load(obj);
	bpf_ir_free_opts(env);
	bpf_ir_free_env(env);
	bpf_object__close(obj);
	return 0;
}
