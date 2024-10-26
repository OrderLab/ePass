// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include "linux/bpf_ir.h"
#include "userspace.h"
#include <stdio.h>

static struct bpf_ir_env *env;

int callback_fn(struct bpf_program *prog, struct bpf_prog_load_opts *opts,
		long cookie)
{
	if (!env->err) {
		bpf_program__set_insns(prog, env->insns, env->insn_cnt);
		printf("New program size: %zu\n", bpf_program__insn_cnt(prog));
		return 0;
	} else {
		return -1;
	}
}

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
	struct builtin_pass_cfg passes[] = {
		// { .name = "add_counter", .param = NULL, .enable = true },
		DEF_BUILTIN_PASS_ENABLE_CFG("add_counter", NULL, NULL),
	};
	struct custom_pass_cfg custom_passes[] = {};
	struct bpf_ir_opts opts = bpf_ir_default_opts();
	opts.custom_pass_num = 0;
	opts.custom_passes = custom_passes;
	opts.builtin_pass_cfg_num = 1;
	opts.builtin_pass_cfg = passes;
	opts.print_mode = BPF_IR_PRINT_DUMP;
	env = bpf_ir_init_env(opts, insn, sz);
	if (!env) {
		return 1;
	}
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
	obj = bpf_object__open(argv[1]);
	bpf_object__load(obj);
	bpf_ir_free_env(env);
	bpf_object__close(obj);
}
