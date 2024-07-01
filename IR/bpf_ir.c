#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
// #include "bpf_ir.h"
#include "array.h"

struct bb_entrance_info {
    size_t entrance;
    size_t pos;
};

int compare_num(const void *a, const void *b) {
    return *(const size_t *)a > *(const size_t *)b;
}

void gen_bb(struct bpf_insn *insns, size_t len) {
    struct array bb_entrance = array_init(sizeof(struct bb_entrance_info));
    // First, scan the code to find all the BB entrances
    for (size_t i = 0; i < len; ++i) {
        struct bpf_insn insn = insns[i];
        __u8 class           = insn.code & 0b00000111;
        __u8 src             = (insn.code & 0b00001000) >> 3;
        __u8 code            = (insn.code & 0b11110000) >> 4;
        // TODO: What if insns[i+1] is a pseudo instruction?
        if (class == 0x05 || class == 0x06) {
            if (code == 0x0) {
                if (class == 0x05) {
                    // JMP class
                    // TODO
                    // Add offset
                    size_t                  pos  = (__s16)i + insn.off + 1;
                    struct bb_entrance_info info = {pos, i};
                    array_push(&bb_entrance, &info);
                } else {
                    // JMP32 class
                    // TODO
                    // Add immediate
                    size_t                  pos  = (__s32)i + insn.imm + 1;
                    struct bb_entrance_info info = {pos, i};
                    array_push(&bb_entrance, &info);
                }
            }
            if ((code >= 0x1 && code <= 0x07) || (code >= 0xa && code <= 0xd)) {
                // Add offset
                size_t                  pos  = (__s16)i + insn.off + 1;
                struct bb_entrance_info info = {pos, i};
                array_push(&bb_entrance, &info);
            }
            if (code == 0x08) {
                // BPF_CALL
                // Unsupported yet
                continue;
            }
            if (i + 1 < len) {
                size_t                  pos  = i + 1;
                struct bb_entrance_info info = {pos, i};
                array_push(&bb_entrance, &info);
            }
        }
    }
    qsort(bb_entrance.data, bb_entrance.num_elem, bb_entrance.elem_size, &compare_num);
    array_push(&bb_entrance, &len);
    // Generate real basic blocks
    size_t pos = 0;
    for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
        size_t entrance = ((size_t *)(bb_entrance.data))[i];
        for (size_t j = pos; j < entrance; ++j) {
        }
        pos = entrance;
    }
}
