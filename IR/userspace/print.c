#include <stdio.h>
#include "bpf/libbpf.h"
#include <linux/bpf_ir.h>

static void print_bpf_prog(struct bpf_ir_env *env, const struct bpf_insn *insns,
			   size_t len)
{
	for (size_t i = 0; i < len; ++i) {
		const struct bpf_insn *insn = &insns[i];
		if (insn->code == 0) {
			continue;
		}
		PRINT_LOG(env, "[%zu] ", i);
		bpf_ir_print_bpf_insn(env, insn);
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
	// bpf_program__set_insns
	struct bpf_ir_opts opts = {
		.debug = 1,
		.print_mode = BPF_IR_PRINT_BPF,
	};
	struct bpf_ir_env *env = bpf_ir_init_env(opts);
	if (!env) {
		return 1;
	}
	print_bpf_prog(env, insn, sz);
	bpf_ir_print_log_dbg(env);
	bpf_ir_free_env(env);
	bpf_object__close(obj);
}
