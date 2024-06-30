#include <linux/bpf.h>
#include <stdio.h>
// #include "bpf_ir.h"
#include "array.h"

void gen_bb(struct bpf_insn *insns, size_t len) {
    struct array bb_entrance = array_init(sizeof(size_t));
    // First, scan the code to find all the BB entrances
    for (size_t i = 0; i < len; ++i) {
        struct bpf_insn insn = insns[i];
        __u8 class           = insn.code & 0b00000111;
        __u8 src             = (insn.code & 0b00001000) >> 3;
        __u8 code            = (insn.code & 0b11110000) >> 4;
        if (class == 0x05 || class == 0x06) {
            if (code == 0x0) {
                if (class == 0x05) {
                    // JMP class
                    // TODO
                    // Add offset
                    size_t pos = (__s16)i + insn.off;
                    array_push(&bb_entrance, &pos);
                } else {
                    // JMP32 class
                    // TODO
                    // Add immediate
                    size_t pos = (__s32)i + insn.imm;
                    array_push(&bb_entrance, &pos);
                }
            }
            if ((code >= 0x1 && code <= 0x07) || (code >= 0xa && code <= 0xd)) {
                // Add offset
                size_t pos = (__s16)i + insn.off;
                array_push(&bb_entrance, &pos);
            }
            if (code == 0x08) {
                // BPF_CALL
                // Unsupported yet
            }
            if (i + 1 < len) {
                size_t pos = i + 1;
                array_push(&bb_entrance, &pos);
            }
        }
    }
    for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
        size_t data = ((int *)(bb_entrance.data))[i];
        printf("%ld\n", data);
    }
}
