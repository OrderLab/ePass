#include <assert.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <stdio.h>
#include <linux/bpf_ir.h>
#include <string.h>

int bpf_ir_run(struct bpf_insn *insns, size_t len)
{
	for (__u32 i = 0; i < len; ++i) {
		struct bpf_insn *insn = &insns[i];
		// printf("insn[%d]: code=%x, dst_reg=%x, src_reg=%x, off=%x, imm=%x\n",
		//        i, insn->code, insn->dst_reg, insn->src_reg, insn->off,
		//        insn->imm);
		__u64 data;
		// assert(sizeof(__u64) == sizeof(struct bpf_insn));
		memcpy(&data, insn, sizeof(struct bpf_insn));
		printf("insn[%d]: %llu\n", i, data);
	}
	return 0;
}
