#include <stdio.h>
#include "bpf/libbpf.h"

int print(const struct bpf_insn *insns, size_t len)
{
	for (__u32 i = 0; i < len; ++i) {
		const struct bpf_insn *insn = &insns[i];
		// printf("insn[%d]: code=%x, dst_reg=%x, src_reg=%x, off=%x, imm=%x\n",
		//        i, insn->code, insn->dst_reg, insn->src_reg, insn->off,
		//        insn->imm);
		__u64 data;
		memcpy(&data, insn, sizeof(struct bpf_insn));
		printf("insn[%d]: %llu\n", i, data);
	}
	return 0;
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
	print(insn, sz);
	bpf_object__close(obj);
}