#include <linux/bpf_common.h>
#include <stdio.h>
#include "read.h"

void run(struct bpf_insn *insns, size_t len) {
    printf("CLASS\tSIZE\tMODE\tOP\tSRC\tIMM\n");
    for (size_t i = 0; i < len; ++i) {
        __u8 code = insns[i].code;
        if (code == 0) {
            continue;
        }
        printf("%02x\t%02x\t%02x\t%02x\t%02x\t%d\n", BPF_CLASS(code), BPF_SIZE(code), BPF_MODE(code),
               BPF_OP(code), BPF_SRC(code), insns[i].imm);
    }
}
