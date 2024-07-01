#include "bpf_ir.h"
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include "array.h"

struct bb_entrance_info {
    size_t                    entrance;
    struct pre_ir_basic_block bb;
};

__u8 class_of_insn(struct bpf_insn insn) {
    return insn.code & 0b00000111;
}

__u8 src_of_insn(struct bpf_insn insn) {
    return (insn.code & 0b00001000) >> 3;
}
__u8 code_of_insn(struct bpf_insn insn) {
    return (insn.code & 0b11110000) >> 4;
}

int compare_num(const void *a, const void *b) {
    struct bb_entrance_info *as = (struct bb_entrance_info *)a;
    struct bb_entrance_info *bs = (struct bb_entrance_info *)b;
    return as->entrance > bs->entrance;
}

void no_dup_push(struct array *arr, size_t val) {
    for (size_t i = 0; i < arr->num_elem; ++i) {
        if (((size_t *)(arr->data))[i] == val) {
            return;
        }
    }
    array_push(arr, &val);
}

// Add current_pos --> entrance_pos in bb_entrances
void add_entrance_info(struct bpf_insn *insns, struct array *bb_entrances, size_t entrance_pos,
                       size_t current_pos) {
    for (size_t i = 0; i < bb_entrances->num_elem; ++i) {
        struct bb_entrance_info *entry = ((struct bb_entrance_info *)(bb_entrances->data)) + i;
        if (entry->entrance == entrance_pos) {
            // Already has this entrance, add a pred
            no_dup_push(&entry->bb.preds, current_pos);
            return;
        }
    }
    // New entrance
    struct array preds    = array_init(sizeof(size_t));
    size_t       last_pos = entrance_pos - 1;
    __u8         code     = code_of_insn(insns[last_pos]);
    if (!(code == 0x09 || code == 0x0)) {
        // BPF_EXIT
        no_dup_push(&preds, last_pos);
    }
    no_dup_push(&preds, current_pos);
    struct bb_entrance_info new_bb;
    new_bb.entrance = entrance_pos;
    new_bb.bb.preds = preds;
    array_push(bb_entrances, &new_bb);
}

// Return the parent BB of a instruction
struct pre_ir_basic_block *get_bb_parent(struct array *bb_entrance, size_t pos) {
    size_t                   bb_id = 0;
    struct bb_entrance_info *bbs   = (struct bb_entrance_info *)(bb_entrance->data);
    for (size_t i = 1; i < bb_entrance->num_elem; ++i) {
        struct bb_entrance_info *entry = bbs + i;
        if (entry->entrance <= pos) {
            bb_id++;
        } else {
            break;
        }
    }
    return bbs[bb_id].bb.self;
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

struct pre_ir_basic_block *gen_bb(struct bpf_insn *insns, size_t len) {
    struct array bb_entrance = array_init(sizeof(struct bb_entrance_info));
    // First, scan the code to find all the BB entrances
    for (size_t i = 0; i < len; ++i) {
        struct bpf_insn insn = insns[i];
        __u8 class           = class_of_insn(insn);
        __u8 src             = src_of_insn(insn);
        __u8 code            = code_of_insn(insn);
        if (class == 0x05 || class == 0x06) {
            if (i + 1 < len && insns[i + 1].code == 0) {
                // TODO: What if insns[i+1] is a pseudo instruction?
                printf("Error");
                exit(-1);
            }
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
                add_entrance_info(insns, &bb_entrance, pos, i);
            }
            if ((code >= 0x1 && code <= 0x07) || (code >= 0xa && code <= 0xd)) {
                // Add offset
                size_t pos = (__s16)i + insn.off + 1;
                add_entrance_info(insns, &bb_entrance, pos, i);
                add_entrance_info(insns, &bb_entrance, i + 1, i);
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

    // Create the first BB (entry block)
    struct bb_entrance_info bb_entry_info;
    bb_entry_info.entrance = 0;
    bb_entry_info.bb.preds = array_null();
    array_push(&bb_entrance, &bb_entry_info);

    // Sort the BBs
    qsort(bb_entrance.data, bb_entrance.num_elem, bb_entrance.elem_size, &compare_num);
    // Generate real basic blocks

    struct bb_entrance_info *all_bbs = ((struct bb_entrance_info *)(bb_entrance.data));

    // Print the BB
    for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
        struct bb_entrance_info entry = all_bbs[i];
        printf("%ld: %ld\n", entry.entrance, entry.bb.preds.num_elem);
    }

    // Init preds
    for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
        struct bb_entrance_info   *entry   = all_bbs + i;
        struct pre_ir_basic_block *real_bb = __malloc(sizeof(struct pre_ir_basic_block));
        real_bb->id                        = i;
        real_bb->self                      = real_bb;
        real_bb->succs                     = array_init(sizeof(struct pre_ir_basic_block *));
        entry->bb.self                     = real_bb;
    }
    for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
        struct bb_entrance_info *entry = all_bbs + i;

        struct array preds     = entry->bb.preds;
        struct array new_preds = array_init(sizeof(struct pre_ir_basic_block *));
        for (size_t j = 0; j < preds.num_elem; ++j) {
            size_t pred_pos = ((size_t *)(preds.data))[j];
            // Get the real parent BB
            struct pre_ir_basic_block *parent_bb = get_bb_parent(&bb_entrance, pred_pos);
            // We push the address to the array
            array_push(&new_preds, &parent_bb);
            // Add entry->bb to the succ of parent_bb
            array_push(&parent_bb->succs, &entry->bb.self);
        }
        array_free(&preds);
        entry->bb.self->preds = new_preds;
    }
    // Return the entry BB
    // TODO: Remove BBs impossible to reach
    struct pre_ir_basic_block *entry_bb = all_bbs[0].bb.self;
    array_free(&bb_entrance);
    return entry_bb;
}

void print_cfg(struct pre_ir_basic_block *bb) {
    printf("BB %ld:\n", bb->id);
    printf("preds (%ld): ", bb->preds.num_elem);
    for (size_t i = 0; i < bb->preds.num_elem; ++i) {
        struct pre_ir_basic_block *pred = ((struct pre_ir_basic_block **)(bb->preds.data))[i];
        printf("%ld ", pred->id);
    }
    printf("\nsuccs (%ld): ", bb->succs.num_elem);
    for (size_t i = 0; i < bb->succs.num_elem; ++i) {
        struct pre_ir_basic_block *pred = ((struct pre_ir_basic_block **)(bb->succs.data))[i];
        printf("%ld ", pred->id);
    }
    printf("\n");
}

void construct_ir(struct bpf_insn *insns, size_t len) {
    struct pre_ir_basic_block *bb_entry = gen_bb(insns, len);
    print_cfg(bb_entry);
}