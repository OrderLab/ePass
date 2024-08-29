#include <linux/bpf_common.h>
#include <stdio.h>
#include <linux/bpf_ir.h>

int bpf_ir_run(struct bpf_insn *insns, size_t len)
{
	for (__u32 i = 0; i < len; ++i) {
		struct bpf_insn *insn = &insns[i];
		printf("insn[%d]: code=%x, dst_reg=%x, src_reg=%x, off=%x, imm=%x\n",
		       i, insn->code, insn->dst_reg, insn->src_reg, insn->off,
		       insn->imm);
	}
	return 0;
}
