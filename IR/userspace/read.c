#include "bpf/libbpf.h"
#include "linux/bpf_ir.h"
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
	// bpf_program__set_insns
	struct bpf_ir_env *env = malloc_proto(sizeof(struct bpf_ir_env));
	bpf_ir_run(env, insn, sz);
	bpf_ir_print_log_dbg(env);
	free_proto(env);
	bpf_object__close(obj);
}
