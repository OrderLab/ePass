#ifndef __BPF_IR_INSN_H__
#define __BPF_IR_INSN_H__

#include "bpf_ir.h"
#include "list.h"

enum insert_position {
    INSERT_BACK,
    INSERT_FRONT,
    // BB-specific
    INSERT_BACK_BEFORE_JMP,
    INSERT_FRONT_AFTER_PHI
};

// Return an array of struct ir_value*
struct array get_operands(struct ir_insn *insn);

void replace_all_usage(struct ir_insn *insn, struct ir_value rep);

void replace_all_usage_except(struct ir_insn *insn, struct ir_value rep, struct ir_insn *except);

void erase_insn(struct ir_insn *insn);

int is_last_insn(struct ir_insn *insn);

// Erase an instruction without checking the users
// Used in code gen
void erase_insn_raw(struct ir_insn *insn);

int is_void(struct ir_insn *insn);

int is_jmp(struct ir_insn *insn);

int is_jmp_cond(struct ir_insn *insn);

struct ir_insn *prev_insn(struct ir_insn *insn);

struct ir_insn *next_insn(struct ir_insn *insn);

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

struct ir_insn *create_assign_insn(struct ir_insn *insn, struct ir_value val,
                                   enum insert_position pos);

struct ir_insn *create_assign_insn_bb(struct ir_basic_block *bb, struct ir_value val,
                                      enum insert_position pos);

struct ir_insn *create_phi_insn(struct ir_insn *insn, enum insert_position pos);

struct ir_insn *create_phi_insn_bb(struct ir_basic_block *bb, enum insert_position pos);

void phi_add_operand(struct ir_insn *insn, struct ir_basic_block *bb, struct ir_value val);

void val_add_user(struct ir_value val, struct ir_insn *user);

void val_remove_user(struct ir_value val, struct ir_insn *user);

struct ir_insn *create_assign_insn_cg(struct ir_insn *insn, struct ir_value val,
                                      enum insert_position pos);

struct ir_insn *create_assign_insn_bb_cg(struct ir_basic_block *bb, struct ir_value val,
                                         enum insert_position pos);

void replace_operand(struct ir_insn *insn, struct ir_value v1, struct ir_value v2);

struct ir_insn *create_insn_base_cg(struct ir_basic_block *bb);

struct ir_insn *create_insn_base(struct ir_basic_block *bb);

void insert_at(struct ir_insn *new_insn, struct ir_insn *insn, enum insert_position pos);

void insert_at_bb(struct ir_insn *new_insn, struct ir_basic_block *bb, enum insert_position pos);

#endif
