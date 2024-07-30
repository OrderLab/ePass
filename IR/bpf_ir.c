#include "bpf_ir.h"
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include "add_stack_offset.h"
#include "array.h"
#include "list.h"
#include "dbg.h"
#include "passes.h"
#include "reachable_bb.h"
#include "read.h"

// TODO: Change this to real function
static __u32 helper_func_arg_num[100] = {1, 1, 1, 1, 1, 1, 2, 1, 1};

int compare_num(const void *a, const void *b) {
    struct bb_entrance_info *as = (struct bb_entrance_info *)a;
    struct bb_entrance_info *bs = (struct bb_entrance_info *)b;
    return as->entrance > bs->entrance;
}

// Add current_pos --> entrance_pos in bb_entrances
void add_entrance_info(struct bpf_insn *insns, struct array *bb_entrances, size_t entrance_pos,
                       size_t current_pos) {
    for (size_t i = 0; i < bb_entrances->num_elem; ++i) {
        struct bb_entrance_info *entry = ((struct bb_entrance_info *)(bb_entrances->data)) + i;
        if (entry->entrance == entrance_pos) {
            // Already has this entrance, add a pred
            array_push_unique(&entry->bb->preds, &current_pos);
            return;
        }
    }
    // New entrance
    struct array preds    = array_init(sizeof(size_t));
    size_t       last_pos = entrance_pos - 1;
    __u8         code     = insns[last_pos].code;
    if (!(BPF_OP(code) == BPF_JA || BPF_OP(code) == BPF_EXIT)) {
        // BPF_EXIT
        array_push_unique(&preds, &last_pos);
    }
    array_push_unique(&preds, &current_pos);
    struct bb_entrance_info new_bb;
    new_bb.entrance  = entrance_pos;
    new_bb.bb        = __malloc(sizeof(struct pre_ir_basic_block));
    new_bb.bb->preds = preds;
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
    return bbs[bb_id].bb;
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
    new_bb.entrance  = entrance_pos;
    new_bb.bb        = __malloc(sizeof(struct pre_ir_basic_block));
    new_bb.bb->preds = preds;
    array_push(bb_entrances, &new_bb);
}

struct ir_basic_block *init_ir_bb_raw() {
    struct ir_basic_block *new_bb = __malloc(sizeof(struct ir_basic_block));
    INIT_LIST_HEAD(&new_bb->ir_insn_head);
    new_bb->user_data = NULL;
    new_bb->preds     = INIT_ARRAY(struct ir_basic_block *);
    new_bb->succs     = INIT_ARRAY(struct ir_basic_block *);
    new_bb->users     = INIT_ARRAY(struct ir_insn *);
    return new_bb;
}

void init_ir_bb(struct pre_ir_basic_block *bb) {
    bb->ir_bb            = init_ir_bb_raw();
    bb->ir_bb->_visited  = 0;
    bb->ir_bb->user_data = bb;
    for (__u8 i = 0; i < MAX_BPF_REG; ++i) {
        bb->incompletePhis[i] = NULL;
    }
}

struct bb_info gen_bb(struct bpf_insn *insns, size_t len) {
    struct array bb_entrance = array_init(sizeof(struct bb_entrance_info));
    // First, scan the code to find all the BB entrances
    for (size_t i = 0; i < len; ++i) {
        struct bpf_insn insn = insns[i];
        __u8            code = insn.code;
        if (BPF_CLASS(code) == BPF_JMP || BPF_CLASS(code) == BPF_JMP32) {
            if (i + 1 < len && insns[i + 1].code == 0) {
                // TODO: What if insns[i+1] is a pseudo instruction?
                CRITICAL("Error");
            }
            if (BPF_OP(code) == BPF_JA) {
                // Direct Jump
                size_t pos = 0;
                if (BPF_CLASS(code) == BPF_JMP) {
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
            if ((BPF_OP(code) >= BPF_JEQ && BPF_OP(code) <= BPF_JSGE) ||
                (BPF_OP(code) >= BPF_JLT && BPF_OP(code) <= BPF_JSLE)) {
                // Add offset
                size_t pos = (__s16)i + insn.off + 1;
                add_entrance_info(insns, &bb_entrance, pos, i);
                add_entrance_info(insns, &bb_entrance, i + 1, i);
            }
            if (BPF_OP(code) == BPF_CALL) {
                // BPF_CALL
                // Unsupported yet
                continue;
            }
            if (BPF_OP(code) == BPF_EXIT) {
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
    bb_entry_info.entrance  = 0;
    bb_entry_info.bb        = __malloc(sizeof(struct pre_ir_basic_block));
    bb_entry_info.bb->preds = array_null();
    array_push(&bb_entrance, &bb_entry_info);

    // Sort the BBs
    qsort(bb_entrance.data, bb_entrance.num_elem, bb_entrance.elem_size, &compare_num);
    // Generate real basic blocks

    struct bb_entrance_info *all_bbs = ((struct bb_entrance_info *)(bb_entrance.data));

    // Print the BB
    // for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
    //     struct bb_entrance_info entry = all_bbs[i];
    //     printf("%ld: %ld\n", entry.entrance, entry.bb->preds.num_elem);
    // }

    // Init preds
    for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
        struct bb_entrance_info   *entry   = all_bbs + i;
        struct pre_ir_basic_block *real_bb = entry->bb;
        real_bb->id                        = i;
        real_bb->succs                     = array_init(sizeof(struct pre_ir_basic_block *));
        real_bb->visited                   = 0;
        real_bb->pre_insns                 = NULL;
        real_bb->start_pos                 = entry->entrance;
        real_bb->end_pos = i + 1 < bb_entrance.num_elem ? all_bbs[i + 1].entrance : len;
        real_bb->filled  = 0;
        real_bb->sealed  = 0;
        real_bb->ir_bb   = NULL;
    }

    // Allocate instructions
    for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
        struct pre_ir_basic_block *real_bb = all_bbs[i].bb;
        real_bb->pre_insns =
            __malloc(sizeof(struct pre_ir_insn) * (real_bb->end_pos - real_bb->start_pos));
        size_t bb_pos = 0;
        for (size_t pos = real_bb->start_pos; pos < real_bb->end_pos; ++pos, ++bb_pos) {
            struct bpf_insn    insn = insns[pos];
            struct pre_ir_insn new_insn;
            new_insn.opcode  = insn.code;
            new_insn.src_reg = insn.src_reg;
            new_insn.dst_reg = insn.dst_reg;
            new_insn.imm     = insn.imm;
            new_insn.imm64   = 0;
            new_insn.off     = insn.off;
            new_insn.pos     = pos;
            if (pos + 1 < real_bb->end_pos && insns[pos + 1].code == 0) {
                __u64 imml     = (__u64)insn.imm & 0xFFFFFFFF;
                new_insn.imm64 = ((__s64)(insns[pos + 1].imm) << 32) | imml;
                pos++;
            }
            real_bb->pre_insns[bb_pos] = new_insn;
        }
        real_bb->len = bb_pos;
    }
    for (size_t i = 0; i < bb_entrance.num_elem; ++i) {
        struct bb_entrance_info *entry = all_bbs + i;

        struct array preds     = entry->bb->preds;
        struct array new_preds = array_init(sizeof(struct pre_ir_basic_block *));
        for (size_t j = 0; j < preds.num_elem; ++j) {
            size_t pred_pos = ((size_t *)(preds.data))[j];
            // Get the real parent BB
            struct pre_ir_basic_block *parent_bb = get_bb_parent(&bb_entrance, pred_pos);
            // We push the address to the array
            array_push(&new_preds, &parent_bb);
            // Add entry->bb to the succ of parent_bb
            array_push(&parent_bb->succs, &entry->bb);
        }
        array_free(&preds);
        entry->bb->preds = new_preds;
    }
    // Return the entry BB
    // TODO: Remove BBs impossible to reach
    struct bb_info ret;
    ret.entry   = all_bbs[0].bb;
    ret.all_bbs = bb_entrance;
    return ret;
}

void print_pre_ir_cfg(struct pre_ir_basic_block *bb) {
    if (bb->visited) {
        return;
    }
    bb->visited = 1;
    printf("BB %ld:\n", bb->id);
    for (size_t i = 0; i < bb->len; ++i) {
        struct pre_ir_insn insn = bb->pre_insns[i];
        printf("%x %x %llx\n", insn.opcode, insn.imm, insn.imm64);
    }
    printf("preds (%ld): ", bb->preds.num_elem);
    for (size_t i = 0; i < bb->preds.num_elem; ++i) {
        struct pre_ir_basic_block *pred = ((struct pre_ir_basic_block **)(bb->preds.data))[i];
        printf("%ld ", pred->id);
    }
    printf("\nsuccs (%ld): ", bb->succs.num_elem);
    for (size_t i = 0; i < bb->succs.num_elem; ++i) {
        struct pre_ir_basic_block *succ = ((struct pre_ir_basic_block **)(bb->succs.data))[i];
        printf("%ld ", succ->id);
    }
    printf("\n\n");
    for (size_t i = 0; i < bb->succs.num_elem; ++i) {
        struct pre_ir_basic_block *succ = ((struct pre_ir_basic_block **)(bb->succs.data))[i];
        print_pre_ir_cfg(succ);
    }
}

struct ssa_transform_env init_env(struct bb_info info) {
    struct ssa_transform_env env;
    for (size_t i = 0; i < MAX_BPF_REG; ++i) {
        env.currentDef[i] = array_init(sizeof(struct bb_val));
    }
    env.info     = info;
    env.sp_users = array_init(sizeof(struct ir_insn *));
    // Initialize function argument
    // TODO: more than one arg
    struct ir_value val;
    val.type        = IR_VALUE_FUNCTIONARG;
    val.data.arg_id = 0;
    write_variable(&env, BPF_REG_1, info.entry, val);
    return env;
}

void seal_block(struct ssa_transform_env *env, struct pre_ir_basic_block *bb) {
    // Seal a BB
    for (__u8 i = 0; i < MAX_BPF_REG; ++i) {
        if (bb->incompletePhis[i]) {
            add_phi_operands(env, i, bb->incompletePhis[i]);
        }
    }
    bb->sealed = 1;
}

void write_variable(struct ssa_transform_env *env, __u8 reg, struct pre_ir_basic_block *bb,
                    struct ir_value val) {
    if (reg >= MAX_BPF_REG - 1) {
        // Stack pointer is read-only
        CRITICAL("Error");
    }
    // Write a variable to a BB
    struct array *currentDef = &env->currentDef[reg];
    // Traverse the array to find if there exists a value in the same BB
    for (size_t i = 0; i < currentDef->num_elem; ++i) {
        struct bb_val *bval = ((struct bb_val *)(currentDef->data)) + i;
        if (bval->bb == bb) {
            // Found
            bval->val = val;
            return;
        }
    }
    // Not found
    struct bb_val new_val;
    new_val.bb  = bb;
    new_val.val = val;
    array_push(currentDef, &new_val);
}

struct ir_insn *add_phi_operands(struct ssa_transform_env *env, __u8 reg, struct ir_insn *insn) {
    // insn must be a (initialized) PHI instruction
    if (insn->op != IR_INSN_PHI) {
        CRITICAL("Not a PHI node");
    }
    for (size_t i = 0; i < insn->parent_bb->preds.num_elem; ++i) {
        struct ir_basic_block *pred = ((struct ir_basic_block **)(insn->parent_bb->preds.data))[i];
        struct phi_value       phi;
        phi.bb    = pred;
        phi.value = read_variable(env, reg, (struct pre_ir_basic_block *)pred->user_data);
        add_user(env, insn, phi.value);
        array_push(&insn->phi, &phi);
    }
    return insn;
}

struct ir_value read_variable_recursive(struct ssa_transform_env *env, __u8 reg,
                                        struct pre_ir_basic_block *bb) {
    struct ir_value val;
    if (!bb->sealed) {
        // Incomplete CFG
        struct ir_insn *new_insn = create_insn_front(bb->ir_bb);
        new_insn->op             = IR_INSN_PHI;
        new_insn->phi            = array_init(sizeof(struct phi_value));
        bb->incompletePhis[reg]  = new_insn;
        val.type                 = IR_VALUE_INSN;
        val.data.insn_d          = new_insn;
    } else if (bb->preds.num_elem == 1) {
        val = read_variable(env, reg, ((struct pre_ir_basic_block **)(bb->preds.data))[0]);
    } else {
        struct ir_insn *new_insn = create_insn_front(bb->ir_bb);
        new_insn->op             = IR_INSN_PHI;
        new_insn->phi            = array_init(sizeof(struct phi_value));
        val.type                 = IR_VALUE_INSN;
        val.data.insn_d          = new_insn;
        write_variable(env, reg, bb, val);
        new_insn        = add_phi_operands(env, reg, new_insn);
        val.type        = IR_VALUE_INSN;
        val.data.insn_d = new_insn;
    }
    write_variable(env, reg, bb, val);
    return val;
}

struct ir_value read_variable(struct ssa_transform_env *env, __u8 reg,
                              struct pre_ir_basic_block *bb) {
    // Read a variable from a BB
    if (reg == BPF_REG_10) {
        // Stack pointer
        struct ir_value val;
        val.type = IR_VALUE_STACK_PTR;
        return val;
    }
    struct array *currentDef = &env->currentDef[reg];
    for (size_t i = 0; i < currentDef->num_elem; ++i) {
        struct bb_val *bval = ((struct bb_val *)(currentDef->data)) + i;
        if (bval->bb == bb) {
            // Found
            return bval->val;
        }
    }
    // Not found
    return read_variable_recursive(env, reg, bb);
}

struct ir_insn *create_insn() {
    struct ir_insn *insn = __malloc(sizeof(struct ir_insn));
    insn->users          = array_init(sizeof(struct ir_insn *));
    return insn;
}

struct ir_insn *create_insn_back(struct ir_basic_block *bb) {
    struct ir_insn *insn = create_insn();
    insn->parent_bb      = bb;
    list_add_tail(&insn->list_ptr, &bb->ir_insn_head);
    return insn;
}

struct ir_insn *create_insn_front(struct ir_basic_block *bb) {
    struct ir_insn *insn = create_insn();
    insn->parent_bb      = bb;
    list_add(&insn->list_ptr, &bb->ir_insn_head);
    return insn;
}

enum ir_vr_type to_ir_ld_s(__u8 size) {
    switch (size) {
        case BPF_W:
            return IR_VR_TYPE_S32;
        case BPF_H:
            return IR_VR_TYPE_S16;
        case BPF_B:
            return IR_VR_TYPE_S8;
        case BPF_DW:
            return IR_VR_TYPE_S64;
        default:
            CRITICAL("Error");
    }
}

enum ir_vr_type to_ir_ld_u(__u8 size) {
    switch (size) {
        case BPF_W:
            return IR_VR_TYPE_U32;
        case BPF_H:
            return IR_VR_TYPE_U16;
        case BPF_B:
            return IR_VR_TYPE_U8;
        case BPF_DW:
            return IR_VR_TYPE_U64;
        default:
            CRITICAL("Error");
    }
}

// User uses val
void add_user(struct ssa_transform_env *env, struct ir_insn *user, struct ir_value val) {
    if (val.type == IR_VALUE_INSN) {
        array_push_unique(&val.data.insn_d->users, &user);
    }
    if (val.type == IR_VALUE_STACK_PTR) {
        array_push_unique(&env->sp_users, &user);
    }
}

/**
    Initialize the IR BBs

    Allocate memory and set the preds and succs.
 */
void init_ir_bbs(struct ssa_transform_env *env) {
    for (size_t i = 0; i < env->info.all_bbs.num_elem; ++i) {
        struct pre_ir_basic_block *bb = ((struct bb_entrance_info *)(env->info.all_bbs.data))[i].bb;
        init_ir_bb(bb);
    }
    // Set the preds and succs
    for (size_t i = 0; i < env->info.all_bbs.num_elem; ++i) {
        struct pre_ir_basic_block *bb = ((struct bb_entrance_info *)(env->info.all_bbs.data))[i].bb;
        struct ir_basic_block     *irbb = bb->ir_bb;
        for (size_t j = 0; j < bb->preds.num_elem; ++j) {
            struct pre_ir_basic_block *pred = ((struct pre_ir_basic_block **)(bb->preds.data))[j];
            array_push(&irbb->preds, &pred->ir_bb);
        }
        for (size_t j = 0; j < bb->succs.num_elem; ++j) {
            struct pre_ir_basic_block *succ = ((struct pre_ir_basic_block **)(bb->succs.data))[j];
            array_push(&irbb->succs, &succ->ir_bb);
        }
    }
}

struct ir_basic_block *get_ir_bb_from_position(struct ssa_transform_env *env, size_t pos) {
    // Iterate through all the BBs
    for (size_t i = 0; i < env->info.all_bbs.num_elem; ++i) {
        struct bb_entrance_info *info = &((struct bb_entrance_info *)(env->info.all_bbs.data))[i];
        if (info->entrance == pos) {
            return info->bb->ir_bb;
        }
    }
    CRITICAL("Error");
}

struct ir_value get_src_value(struct ssa_transform_env *env, struct pre_ir_basic_block *bb,
                              struct pre_ir_insn insn) {
    __u8 code = insn.opcode;
    if (BPF_SRC(code) == BPF_K) {
        struct ir_constant c;
        c.data.s32_d = insn.imm;
        c.type       = IR_CONSTANT_S32;
        return (struct ir_value){.type = IR_VALUE_CONSTANT, .data.constant_d = c};
    } else if (BPF_SRC(code) == BPF_X) {
        return read_variable(env, insn.src_reg, bb);
    } else {
        CRITICAL("Error");
    }
}
struct ir_insn *create_alu_bin(struct ir_basic_block *bb, struct ir_value val1,
                               struct ir_value val2, enum ir_insn_type ty,
                               struct ssa_transform_env *env) {
    struct ir_insn *new_insn = create_insn_back(bb);
    new_insn->op             = ty;
    new_insn->values[0]      = val1;
    new_insn->values[1]      = val2;
    new_insn->value_num      = 2;
    add_user(env, new_insn, new_insn->values[0]);
    add_user(env, new_insn, new_insn->values[1]);
    return new_insn;
}

void alu_write(struct ssa_transform_env *env, enum ir_insn_type ty, struct pre_ir_insn insn,
               struct pre_ir_basic_block *bb) {
    struct ir_insn *new_insn = create_alu_bin(bb->ir_bb, read_variable(env, insn.dst_reg, bb),
                                              get_src_value(env, bb, insn), ty, env);
    struct ir_value new_val;
    new_val.type        = IR_VALUE_INSN;
    new_val.data.insn_d = new_insn;
    write_variable(env, insn.dst_reg, bb, new_val);
}

void transform_bb(struct ssa_transform_env *env, struct pre_ir_basic_block *bb) {
    printf("Transforming BB%zu\n", bb->id);
    if (bb->sealed) {
        return;
    }
    // Try sealing a BB
    __u8 pred_all_filled = 1;
    for (size_t i = 0; i < bb->preds.num_elem; ++i) {
        struct pre_ir_basic_block *pred = ((struct pre_ir_basic_block **)(bb->preds.data))[i];
        if (!pred->filled) {
            // Not filled
            pred_all_filled = 0;
            break;
        }
    }
    if (pred_all_filled) {
        seal_block(env, bb);
    }
    if (bb->filled) {
        // Already visited (filled)
        return;
    }
    // Fill the BB
    for (size_t i = 0; i < bb->len; ++i) {
        struct pre_ir_insn insn = bb->pre_insns[i];
        __u8               code = insn.opcode;
        if (BPF_CLASS(code) == BPF_ALU || BPF_CLASS(code) == BPF_ALU64) {
            // 32-bit ALU class
            // TODO: 64-bit ALU class
            if (BPF_OP(code) == BPF_ADD) {
                alu_write(env, IR_INSN_ADD, insn, bb);
            } else if (BPF_OP(code) == BPF_SUB) {
                alu_write(env, IR_INSN_SUB, insn, bb);
            } else if (BPF_OP(code) == BPF_MUL) {
                alu_write(env, IR_INSN_MUL, insn, bb);
            } else if (BPF_OP(code) == BPF_MOV) {
                // Do not create instructions
                write_variable(env, insn.dst_reg, bb, get_src_value(env, bb, insn));
            } else if (BPF_OP(code) == BPF_LSH) {
                alu_write(env, IR_INSN_LSH, insn, bb);
            } else if (BPF_OP(code) == BPF_MOD) {
                // dst = (src != 0) ? (dst % src) : dst
                alu_write(env, IR_INSN_MOD, insn, bb);
            }

            else {
                // TODO
                CRITICAL("Error");
            }

        } else if (BPF_CLASS(code) == BPF_LD && BPF_MODE(code) == BPF_IMM &&
                   BPF_SIZE(code) == BPF_DW) {
            // 64-bit immediate load
            if (insn.src_reg == 0x0) {
                // immediate value
                struct ir_value imm_val;
                imm_val.type                       = IR_VALUE_CONSTANT;
                imm_val.data.constant_d.type       = IR_CONSTANT_U64;
                imm_val.data.constant_d.data.u64_d = insn.imm64;
                write_variable(env, insn.dst_reg, bb, imm_val);
            } else {
                CRITICAL("Not supported");
            }
        } else if (BPF_CLASS(code) == BPF_LDX && BPF_MODE(code) == BPF_MEMSX) {
            // dst = *(signed size *) (src + offset)
            // https://www.kernel.org/doc/html/v6.6/bpf/standardization/instruction-set.html#sign-extension-load-operations

            struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
            new_insn->op             = IR_INSN_LOADRAW;
            struct ir_address_value addr_val;
            addr_val.value = read_variable(env, insn.src_reg, bb);
            add_user(env, new_insn, addr_val.value);
            addr_val.offset    = insn.off;
            new_insn->vr_type  = to_ir_ld_u(BPF_SIZE(code));
            new_insn->addr_val = addr_val;

            struct ir_value new_val;
            new_val.type        = IR_VALUE_INSN;
            new_val.data.insn_d = new_insn;
            write_variable(env, insn.dst_reg, bb, new_val);
        } else if (BPF_CLASS(code) == BPF_LDX && BPF_MODE(code) == BPF_MEM) {
            // Regular load
            // dst = *(unsigned size *) (src + offset)
            // https://www.kernel.org/doc/html/v6.6/bpf/standardization/instruction-set.html#regular-load-and-store-operations
            // TODO: use LOAD instead of LOADRAW
            struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
            new_insn->op             = IR_INSN_LOADRAW;
            struct ir_address_value addr_val;
            addr_val.value = read_variable(env, insn.src_reg, bb);
            add_user(env, new_insn, addr_val.value);
            addr_val.offset    = insn.off;
            new_insn->vr_type  = to_ir_ld_u(BPF_SIZE(code));
            new_insn->addr_val = addr_val;

            struct ir_value new_val;
            new_val.type        = IR_VALUE_INSN;
            new_val.data.insn_d = new_insn;
            write_variable(env, insn.dst_reg, bb, new_val);
        } else if (BPF_CLASS(code) == BPF_ST && BPF_MODE(code) == BPF_MEM) {
            // *(size *) (dst + offset) = imm32
            struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
            new_insn->op             = IR_INSN_STORERAW;
            struct ir_address_value addr_val;
            addr_val.value = read_variable(env, insn.dst_reg, bb);
            add_user(env, new_insn, addr_val.value);
            addr_val.offset                                = insn.off;
            new_insn->vr_type                              = to_ir_ld_u(BPF_SIZE(code));
            new_insn->addr_val                             = addr_val;
            new_insn->values[0].type                       = IR_VALUE_CONSTANT;
            new_insn->values[0].data.constant_d.type       = IR_CONSTANT_S32;
            new_insn->values[0].data.constant_d.data.s32_d = insn.imm;
            new_insn->value_num                            = 1;
        } else if (BPF_CLASS(code) == BPF_STX && BPF_MODE(code) == BPF_MEM) {
            // *(size *) (dst + offset) = src
            struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
            new_insn->op             = IR_INSN_STORERAW;
            struct ir_address_value addr_val;
            addr_val.value = read_variable(env, insn.dst_reg, bb);
            add_user(env, new_insn, addr_val.value);
            addr_val.offset     = insn.off;
            new_insn->vr_type   = to_ir_ld_u(BPF_SIZE(code));
            new_insn->addr_val  = addr_val;
            new_insn->values[0] = read_variable(env, insn.src_reg, bb);
            new_insn->value_num = 1;
            add_user(env, new_insn, new_insn->values[0]);
        } else if (BPF_CLASS(code) == BPF_JMP) {
            if (BPF_OP(code) == BPF_JA) {
                // Direct Jump
                // PC += offset
                struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
                new_insn->op             = IR_INSN_JA;
                size_t pos               = insn.pos + insn.off + 1;
                new_insn->bb1            = get_ir_bb_from_position(env, pos);
                array_push(&new_insn->bb1->users, &new_insn);
            } else if (BPF_OP(code) == BPF_EXIT) {
                // Exit
                struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
                new_insn->op             = IR_INSN_RET;
                new_insn->values[0]      = read_variable(env, BPF_REG_0, bb);
                new_insn->value_num      = 1;
            } else if (BPF_OP(code) == BPF_JEQ) {
                // PC += offset if dst == src
                struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
                new_insn->op             = IR_INSN_JEQ;
                new_insn->values[0]      = read_variable(env, insn.dst_reg, bb);
                new_insn->values[1]      = get_src_value(env, bb, insn);
                new_insn->value_num      = 2;
                add_user(env, new_insn, new_insn->values[0]);
                add_user(env, new_insn, new_insn->values[1]);
                size_t pos    = insn.pos + insn.off + 1;
                new_insn->bb1 = get_ir_bb_from_position(env, insn.pos + 1);
                new_insn->bb2 = get_ir_bb_from_position(env, pos);
                array_push(&new_insn->bb1->users, &new_insn);
                array_push(&new_insn->bb2->users, &new_insn);
            } else if (BPF_OP(code) == BPF_JLT) {
                // PC += offset if dst < src
                struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
                new_insn->op             = IR_INSN_JLT;
                new_insn->values[0]      = read_variable(env, insn.dst_reg, bb);
                new_insn->values[1]      = get_src_value(env, bb, insn);
                new_insn->value_num      = 2;
                add_user(env, new_insn, new_insn->values[0]);
                add_user(env, new_insn, new_insn->values[1]);
                size_t pos    = insn.pos + insn.off + 1;
                new_insn->bb1 = get_ir_bb_from_position(env, insn.pos + 1);
                new_insn->bb2 = get_ir_bb_from_position(env, pos);
                array_push(&new_insn->bb1->users, &new_insn);
                array_push(&new_insn->bb2->users, &new_insn);
            } else if (BPF_OP(code) == BPF_JLE) {
                // PC += offset if dst <= src
                struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
                new_insn->op             = IR_INSN_JLE;
                new_insn->values[0]      = read_variable(env, insn.dst_reg, bb);
                new_insn->values[1]      = get_src_value(env, bb, insn);
                new_insn->value_num      = 2;
                add_user(env, new_insn, new_insn->values[0]);
                add_user(env, new_insn, new_insn->values[1]);
                size_t pos    = insn.pos + insn.off + 1;
                new_insn->bb1 = get_ir_bb_from_position(env, insn.pos + 1);
                new_insn->bb2 = get_ir_bb_from_position(env, pos);
                array_push(&new_insn->bb1->users, &new_insn);
                array_push(&new_insn->bb2->users, &new_insn);
            } else if (BPF_OP(code) == BPF_JGT) {
                // PC += offset if dst > src
                struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
                new_insn->op             = IR_INSN_JGT;
                new_insn->values[0]      = read_variable(env, insn.dst_reg, bb);
                new_insn->values[1]      = get_src_value(env, bb, insn);
                new_insn->value_num      = 2;
                add_user(env, new_insn, new_insn->values[0]);
                add_user(env, new_insn, new_insn->values[1]);
                size_t pos    = insn.pos + insn.off + 1;
                new_insn->bb1 = get_ir_bb_from_position(env, insn.pos + 1);
                new_insn->bb2 = get_ir_bb_from_position(env, pos);
                array_push(&new_insn->bb1->users, &new_insn);
                array_push(&new_insn->bb2->users, &new_insn);
            } else if (BPF_OP(code) == BPF_JGE) {
                // PC += offset if dst >= src
                struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
                new_insn->op             = IR_INSN_JGE;
                new_insn->values[0]      = read_variable(env, insn.dst_reg, bb);
                new_insn->values[1]      = get_src_value(env, bb, insn);
                new_insn->value_num      = 2;
                add_user(env, new_insn, new_insn->values[0]);
                add_user(env, new_insn, new_insn->values[1]);
                size_t pos    = insn.pos + insn.off + 1;
                new_insn->bb1 = get_ir_bb_from_position(env, insn.pos + 1);
                new_insn->bb2 = get_ir_bb_from_position(env, pos);
                array_push(&new_insn->bb1->users, &new_insn);
                array_push(&new_insn->bb2->users, &new_insn);
            } else if (BPF_OP(code) == BPF_JNE) {
                // PC += offset if dst != src
                struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
                new_insn->op             = IR_INSN_JNE;
                new_insn->values[0]      = read_variable(env, insn.dst_reg, bb);
                new_insn->values[1]      = get_src_value(env, bb, insn);
                new_insn->value_num      = 2;
                add_user(env, new_insn, new_insn->values[0]);
                add_user(env, new_insn, new_insn->values[1]);
                size_t pos    = insn.pos + insn.off + 1;
                new_insn->bb1 = get_ir_bb_from_position(env, insn.pos + 1);
                new_insn->bb2 = get_ir_bb_from_position(env, pos);
                array_push(&new_insn->bb1->users, &new_insn);
                array_push(&new_insn->bb2->users, &new_insn);
            } else if (BPF_OP(code) == BPF_CALL) {
                // imm is the function id
                struct ir_insn *new_insn = create_insn_back(bb->ir_bb);
                new_insn->op             = IR_INSN_CALL;
                new_insn->fid            = insn.imm;
                if (insn.imm < 0) {
                    printf("Not supported function call\n");
                    new_insn->value_num = 0;
                } else {
                    new_insn->value_num = helper_func_arg_num[insn.imm];
                    if (new_insn->value_num > MAX_FUNC_ARG) {
                        CRITICAL("Too many arguments");
                    }
                    for (size_t j = 0; j < new_insn->value_num; ++j) {
                        new_insn->values[j] = read_variable(env, BPF_REG_1 + j, bb);
                        add_user(env, new_insn, new_insn->values[j]);
                    }
                }

                struct ir_value new_val;
                new_val.type        = IR_VALUE_INSN;
                new_val.data.insn_d = new_insn;
                write_variable(env, BPF_REG_0, bb, new_val);
            } else {
                // TODO
                CRITICAL("Error");
            }
        } else {
            // TODO
            printf("Class 0x%02x not supported\n", BPF_CLASS(code));
            CRITICAL("Error");
        }
    }
    bb->filled = 1;
    // Finish filling
    for (size_t i = 0; i < bb->succs.num_elem; ++i) {
        struct pre_ir_basic_block *succ = ((struct pre_ir_basic_block **)(bb->succs.data))[i];
        transform_bb(env, succ);
    }
}

void free_function(struct ir_function *fun) {
    array_free(&fun->sp_users);
    for (size_t i = 0; i < fun->all_bbs.num_elem; ++i) {
        struct ir_basic_block *bb = ((struct ir_basic_block **)(fun->all_bbs.data))[i];

        array_free(&bb->preds);
        array_free(&bb->succs);
        array_free(&bb->users);
        // Free the instructions
        struct ir_insn *pos, *n;
        list_for_each_entry_safe(pos, n, &bb->ir_insn_head, list_ptr) {
            list_del(&pos->list_ptr);
            array_free(&pos->users);
            if (pos->op == IR_INSN_PHI) {
                array_free(&pos->phi);
            }
            free(pos);
        }
        free(bb);
    }
}

struct ir_function gen_function(struct ssa_transform_env *env) {
    struct ir_function fun;
    fun.arg_num       = 1;
    fun.entry         = env->info.entry->ir_bb;
    fun.sp_users      = env->sp_users;
    fun.all_bbs       = array_init(sizeof(struct ir_basic_block *));
    fun.reachable_bbs = array_init(sizeof(struct ir_basic_block *));
    for (size_t i = 0; i < MAX_BPF_REG; ++i) {
        struct array *currentDef = &env->currentDef[i];
        array_free(currentDef);
    }
    for (size_t i = 0; i < env->info.all_bbs.num_elem; ++i) {
        struct pre_ir_basic_block *bb = ((struct bb_entrance_info *)(env->info.all_bbs.data))[i].bb;
        array_free(&bb->preds);
        array_free(&bb->succs);
        free(bb->pre_insns);
        bb->ir_bb->user_data = NULL;
        array_push(&fun.all_bbs, &bb->ir_bb);
        free(bb);
    }
    return fun;
}

__u8 ir_value_equal(struct ir_value a, struct ir_value b) {
    if (a.type != b.type) {
        return 0;
    }
    if (a.type == IR_VALUE_CONSTANT) {
        return a.data.constant_d.data.s32_d == b.data.constant_d.data.s32_d;
    }
    if (a.type == IR_VALUE_FUNCTIONARG) {
        return a.data.arg_id == b.data.arg_id;
    }
    if (a.type == IR_VALUE_INSN) {
        return a.data.insn_d == b.data.insn_d;
    }
    if (a.type == IR_VALUE_STACK_PTR) {
        return 1;
    }
    CRITICAL("Error");
}

void run_passes(struct ir_function *fun) {
    for (size_t i = 0; i < sizeof(passes) / sizeof(passes[0]); ++i) {
        clean_env(fun);
        gen_reachable_bbs(fun);
        passes[i](fun);
    }
}

// Interface implementation

void run(struct bpf_insn *insns, size_t len) {
    struct bb_info info = gen_bb(insns, len);
    print_pre_ir_cfg(info.entry);
    struct ssa_transform_env env = init_env(info);
    init_ir_bbs(&env);
    transform_bb(&env, info.entry);
    struct ir_function fun = gen_function(&env);
    // Drop env
    print_ir_prog(&fun);
    printf("--------------------\n");
    // Start IR manipulation

    run_passes(&fun);

    // End IR manipulation
    printf("--------------------\n");
    print_ir_prog(&fun);

    // Test
    // add_stack_offset(&fun, -8);
    // printf("--------------------\n");
    // print_ir_prog(&fun);

    // Free the memory
    free_function(&fun);
}
