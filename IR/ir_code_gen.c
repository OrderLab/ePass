#include <linux/bpf.h>
#include <stdio.h>
#include "array.h"
#include "bpf_ir.h"
#include "code_gen.h"
#include "dbg.h"
#include "ir_insn.h"
#include "list.h"
#include "ir_helper.h"

struct ir_insn_cg_extra *init_insn_cg(struct ir_insn *insn) {
    struct ir_insn_cg_extra *extra = __malloc(sizeof(struct ir_insn_cg_extra));
    // When init, the destination is itself
    if (is_void(insn)) {
        extra->dst = NULL;
    } else {
        extra->dst = insn;
    }
    extra->adj            = INIT_ARRAY(struct ir_insn *);
    extra->allocated      = 0;
    extra->spilled        = 0;
    extra->alloc_reg      = 0;
    extra->gen            = INIT_ARRAY(struct ir_insn *);
    extra->kill           = INIT_ARRAY(struct ir_insn *);
    extra->in             = INIT_ARRAY(struct ir_insn *);
    extra->out            = INIT_ARRAY(struct ir_insn *);
    extra->translated_num = 0;
    insn->user_data       = extra;
    return extra;
}

void init_cg(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = __malloc(sizeof(struct ir_bb_cg_extra));
        // Empty bb cg
        bb->user_data = bb_cg;

        struct ir_insn *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            init_insn_cg(insn);
        }
    }

    for (__u8 i = 0; i < MAX_BPF_REG; ++i) {
        fun->cg_info.regs[i] = __malloc(sizeof(struct ir_insn));
        // Those should be read-only
        struct ir_insn *insn           = fun->cg_info.regs[i];
        insn->op                       = IR_INSN_REG;
        insn->parent_bb                = NULL;
        insn->users                    = INIT_ARRAY(struct ir_insn *);
        insn->value_num                = 0;
        struct ir_insn_cg_extra *extra = init_insn_cg(insn);
        extra->alloc_reg               = i;
        extra->dst                     = insn;
        // Pre-colored registers are allocated
        extra->allocated = 1;
        extra->spilled   = 0;
    }
}

void free_insn_cg(struct ir_insn *insn) {
    struct ir_insn_cg_extra *extra = insn_cg(insn);
    array_free(&extra->adj);
    array_free(&extra->gen);
    array_free(&extra->kill);
    array_free(&extra->in);
    array_free(&extra->out);
    __free(extra);
    insn->user_data = NULL;
}

void free_cg_res(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb    = *pos;
        struct ir_bb_cg_extra *bb_cg = bb->user_data;
        __free(bb_cg);
        bb->user_data = NULL;
        struct ir_insn *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            free_insn_cg(insn);
        }
    }

    for (__u8 i = 0; i < MAX_BPF_REG; ++i) {
        struct ir_insn *insn = fun->cg_info.regs[i];
        array_free(&insn->users);
        free_insn_cg(insn);
        __free(insn);
    }
}

void clean_insn_cg(struct ir_insn *insn) {
    struct ir_insn_cg_extra *extra = insn_cg(insn);
    array_clear(&extra->adj);
    array_clear(&extra->gen);
    array_clear(&extra->kill);
    array_clear(&extra->in);
    array_clear(&extra->out);
}

void clean_cg(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            clean_insn_cg(insn);
            struct ir_insn_cg_extra *extra = insn_cg(insn);
            extra->allocated               = 0;
            extra->spilled                 = 0;
            extra->alloc_reg               = 0;
        }
    }

    for (__u8 i = 0; i < MAX_BPF_REG; ++i) {
        struct ir_insn *insn = fun->cg_info.regs[i];
        clean_insn_cg(insn);
    }
    array_clear(&fun->cg_info.all_var);
}

struct ir_insn_cg_extra *insn_cg(struct ir_insn *insn) {
    return insn->user_data;
}

struct ir_insn *dst(struct ir_insn *insn) {
    return insn_cg(insn)->dst;
}

void print_ir_prog_pre_cg(struct ir_function *fun) {
    printf("-----------------\n");
    print_ir_prog_advanced(fun, NULL, NULL, NULL);
}

void print_ir_prog_cg_dst(struct ir_function *fun) {
    printf("-----------------\n");
    print_ir_prog_advanced(fun, NULL, NULL, print_ir_dst);
}

void print_ir_prog_cg_alloc(struct ir_function *fun) {
    printf("-----------------\n");
    print_ir_prog_advanced(fun, NULL, NULL, print_ir_alloc);
}

void synthesize(struct ir_function *fun) {
    // The last step, synthesizes the program
    fun->cg_info.prog = __malloc(fun->cg_info.prog_size * sizeof(struct bpf_insn));
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            struct ir_insn_cg_extra *extra = insn_cg(insn);
            for (__u8 i = 0; i < extra->translated_num; ++i) {
                struct pre_ir_insn translated_insn = extra->translated[i];
                printf("Writing to insn %zu\n", translated_insn.pos);
                struct bpf_insn   *real_insn       = &fun->cg_info.prog[translated_insn.pos];
                real_insn->code                    = translated_insn.opcode;
                real_insn->dst_reg                 = translated_insn.dst_reg;
                real_insn->src_reg                 = translated_insn.src_reg;
                real_insn->off                     = translated_insn.off;
                if (translated_insn.it == IMM) {
                    real_insn->imm = translated_insn.imm;
                } else {
                    // Wide instruction
                    struct bpf_insn *real_insn2 = &fun->cg_info.prog[translated_insn.pos + 1];
                    real_insn->imm              = translated_insn.imm64 & 0xffffffff;
                    real_insn2->imm             = translated_insn.imm64 >> 32;
                }
            }
        }
    }
}

void code_gen(struct ir_function *fun) {
    // Preparation

    prog_check(fun);

    // Step 1: Flag all raw stack access
    add_stack_offset_pre_cg(fun);

    prog_check(fun);

    // Step 2: Eliminate SSA
    to_cssa(fun);
    prog_check(fun);
    print_ir_prog_pre_cg(fun);

    // Init CG, start real code generation
    init_cg(fun);

    // Debugging settings
    fun->cg_info.spill_callee = 0;

    // Step 3: Use explicit real registers
    explicit_reg(fun);  // Still in SSA form, users are available
    print_ir_prog_pre_cg(fun);
    print_ir_prog_cg_dst(fun);

    // Step 4: SSA Destruction
    // users not available from now on
    remove_phi(fun);
    print_ir_prog_cg_dst(fun);

    int need_spill = 1;

    while (need_spill) {
        // Step 5: Liveness Analysis
        liveness_analysis(fun);

        // Step 6: Conflict Analysis
        conflict_analysis(fun);
        print_interference_graph(fun);
        printf("-------------\n");

        // Step 7: Graph coloring
        graph_coloring(fun);
        coaleasing(fun);
        print_interference_graph(fun);
        print_ir_prog_cg_alloc(fun);

        // Step 8: Check if need to spill and spill
        need_spill = check_need_spill(fun);
        if (need_spill) {
            // Still need to spill
            printf("Need to spill...\n");
            clean_cg(fun);
        }
    }

    // Register allocation finished (All registers are fixed)
    printf("Register allocation finished\n");
    print_ir_prog_cg_alloc(fun);

    // Step 9: Calculate stack size
    if (fun->cg_info.spill_callee) {
        calc_callee_num(fun);
    }
    calc_stack_size(fun);

    // Step 10: Shift raw stack operations
    add_stack_offset(fun, fun->cg_info.stack_offset);
    print_ir_prog_cg_alloc(fun);

    // Step 11: Spill callee saved registers
    if (fun->cg_info.spill_callee) {
        spill_callee(fun);
        print_ir_prog_cg_alloc(fun);
    }

    // Step 12: Normalize
    normalize(fun);
    print_ir_prog_cg_alloc(fun);

    // // Step 13: Direct Translation
    // translate(fun);

    // // Step 14: Relocation
    // relocate(fun);

    // // Step 15: Synthesize
    // synthesize(fun);

    // Free CG resources
    free_cg_res(fun);
}
