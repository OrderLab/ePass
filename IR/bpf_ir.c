#include "bpf_ir.h"
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include "array.h"

struct bb_entrance_info {
    size_t                    entrance;
    struct pre_ir_basic_block bb;
};

int compare_num(const void *a, const void *b) {
    struct bb_entrance_info *as = (struct bb_entrance_info *)a;
    struct bb_entrance_info *bs = (struct bb_entrance_info *)b;
    return as->entrance > bs->entrance;
}

// Add current_pos --> entrance_pos in bb_entrances
void add_entrance_info(struct array *bb_entrances, size_t entrance_pos, size_t current_pos) {
    for (size_t i = 0; i < bb_entrances->num_elem; ++i) {
        struct bb_entrance_info *entry = ((struct bb_entrance_info *)(bb_entrances->data)) + i;
        if (entry->entrance == entrance_pos) {
            // Already has this entrance, add a pred
            array_push(&entry->bb.preds, &current_pos);
            return;
        }
    }
    // New entrance
    struct array preds = array_init(sizeof(size_t));
    array_push(&preds, &current_pos);
    struct bb_entrance_info new_bb;
    new_bb.entrance = entrance_pos;
    new_bb.bb.preds = preds;
    array_push(bb_entrances, &new_bb);
}
void init_entrance_info(struct array *bb_entrances, size_t entrance_pos) {
    for (size_t i = 0; i < bb_entrances->num_elem; ++i) {
        struct bb_entrance_info *entry = ((struct bb_entrance_info *)(bb_entrances->data)) + i;
        if (entry->entrance == entrance_pos) {
            // Already has this entrance
            return;
        }
    }
    // New entrance
    struct array            preds = array_init(sizeof(size_t));
    struct bb_entrance_info new_bb;
    new_bb.entrance = entrance_pos;
    new_bb.bb.preds = preds;
    array_push(bb_entrances, &new_bb);
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
        if (i + 1 < len && insns[i + 1].code == 0) {
            // TODO
            exit(-1);
        }
        if (class == 0x05 || class == 0x06) {
            if (code == 0x0) {
                // Direct Jump
                size_t pos = 0;
                if (class == 0x05) {
                    // JMP class (64 bits)
                    // TODO
                    // Add offset
                    pos = (__s16)i + insn.off + 1;
                } else {
                    // JMP32 class
                    // TODO
                    // Add immediate
                    pos = (__s32)i + insn.imm + 1;
                }
                // Add to bb entrance
                // This is one-way control flow
                add_entrance_info(&bb_entrance, pos, i);
            }
            if ((code >= 0x1 && code <= 0x07) || (code >= 0xa && code <= 0xd)) {
                // Add offset
                size_t pos = (__s16)i + insn.off + 1;
                add_entrance_info(&bb_entrance, pos, i);
            }
            if (code == 0x08) {
                // BPF_CALL
                // Unsupported yet
                continue;
            }
            if (code == 0x09) {
                // BPF_EXIT
                if (i + 1 < len) {
                    // Not the last instruction
                    init_entrance_info(&bb_entrance, i + 1);
                }
            }
        }
    }
    qsort(bb_entrance.data, bb_entrance.num_elem, bb_entrance.elem_size, &compare_num);
    // Generate real basic blocks
    for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
        struct bb_entrance_info entry = ((struct bb_entrance_info *)(bb_entrance.data))[i];
        printf("%ld: %ld\n", entry.entrance, entry.bb.preds.num_elem);
    }
}
