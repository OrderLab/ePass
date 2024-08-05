#ifndef __BPF_IR_INSN_H__
#define __BPF_IR_INSN_H__

#include "bpf_ir.h"

enum insert_position {
    INSERT_BACK,
    INSERT_FRONT,
    // BB-specific
    INSERT_BACK_BEFORE_JMP,
    INSERT_FRONT_AFTER_PHI
};

// Return an array of struct ir_value*
struct array get_operands(struct ir_insn *insn);

void erase_insn(struct ir_insn *insn);

int is_void(struct ir_insn *insn);

int is_jmp(struct ir_insn *insn);

struct ir_insn *prev_insn(struct ir_insn *insn);

struct ir_insn *create_alloc_insn(struct ir_insn *insn, enum ir_vr_type type,
                                  enum insert_position pos);

struct ir_insn *create_alloc_insn_bb(struct ir_basic_block *bb, enum ir_vr_type type,
                                     enum insert_position pos);

struct ir_insn *create_store_insn(struct ir_insn *insn, struct ir_insn *st_insn,
                                  struct ir_value val, enum insert_position pos);

struct ir_insn *create_store_insn_bb(struct ir_basic_block *bb, struct ir_insn *st_insn,
                                     struct ir_value val, enum insert_position pos);

struct ir_insn *create_load_insn(struct ir_insn *insn, enum ir_vr_type ty, struct ir_value val,
                                 enum insert_position pos);

struct ir_insn *create_load_insn_bb(struct ir_basic_block *bb, enum ir_vr_type ty,
                                    struct ir_value val, enum insert_position pos);

struct ir_insn *create_bin_insn(struct ir_insn *insn, struct ir_value val1, struct ir_value val2,
                                enum ir_insn_type ty, enum insert_position pos);

struct ir_insn *create_bin_insn_bb(struct ir_basic_block *bb, struct ir_value val1,
                                   struct ir_value val2, enum ir_insn_type ty,
                                   enum insert_position pos);

struct ir_insn *create_ja_insn(struct ir_insn *insn, struct ir_basic_block *to_bb,
                               enum insert_position pos);

struct ir_insn *create_ja_insn_bb(struct ir_basic_block *bb, struct ir_basic_block *to_bb,
                                  enum insert_position pos);

struct ir_insn *create_jbin_insn(struct ir_insn *insn, struct ir_value val1, struct ir_value val2,
                                 struct ir_basic_block *to_bb1, struct ir_basic_block *to_bb2,
                                 enum ir_insn_type ty, enum insert_position pos);

struct ir_insn *create_jbin_insn_bb(struct ir_basic_block *bb, struct ir_value val1,
                                    struct ir_value val2, struct ir_basic_block *to_bb1,
                                    struct ir_basic_block *to_bb2, enum ir_insn_type ty,
                                    enum insert_position pos);

struct ir_insn *create_ret_insn(struct ir_insn *insn, struct ir_value val,
                                enum insert_position pos);

struct ir_insn *create_ret_insn_bb(struct ir_basic_block *bb, struct ir_value val,
                                   enum insert_position pos);

#endif
