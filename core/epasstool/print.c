// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include "epasstool.h"

static void print_bpf_prog(struct bpf_ir_env *env, const struct bpf_insn *insns,
			   size_t len)
{
	for (size_t i = 0; i < len; ++i) {
		const struct bpf_insn *insn = &insns[i];
		if (insn->code == 0) {
			continue;
		}
		PRINT_LOG_DEBUG(env, "[%zu] ", i);
		bpf_ir_print_bpf_insn(env, insn);
	}
}

int print(struct user_opts uopts)
{
	struct bpf_object *obj = bpf_object__open(uopts.prog);

	struct bpf_program *prog = NULL;
	if (uopts.auto_sec) {
		prog = bpf_object__next_program(obj, NULL);
	} else {
		prog = bpf_object__find_program_by_name(obj, uopts.sec);
	}

	if (!prog) {
		return 1;
	}
	size_t sz = bpf_program__insn_cnt(prog);
	const struct bpf_insn *insn = bpf_program__insns(prog);
	struct bpf_ir_opts opts = bpf_ir_default_opts();
	opts.verbose = 3;
	struct bpf_ir_env *env = bpf_ir_init_env(opts, insn, sz);
	if (!env) {
		return 1;
	}
	print_bpf_prog(env, insn, sz);
	// bpf_ir_print_log_dbg(env);
	bpf_ir_free_env(env);
	bpf_object__close(obj);
	return 0;
}
