#include "prog_check.h"
#include "array.h"
#include "bpf_ir.h"
#include "dbg.h"
#include "ir_insn.h"
#include "list.h"

void check_insn_users_use_insn(struct ir_insn *insn) {
    struct ir_insn **pos;
    array_for(pos, insn->users) {
        struct ir_insn *user = *pos;
        // Check if the user actually uses this instruction
        struct array      operands = get_operands(user);
        struct ir_value **val;
        int               found = 0;
        array_for(val, operands) {
            struct ir_value *v = *val;
            if (v->type == IR_VALUE_INSN && v->data.insn_d == insn) {
                // Found the user
                found = 1;
                break;
            }
        }
        array_free(&operands);
        if (!found) {
            // Error!
            CRITICAL("User does not use the instruction");
        }
    }
}

void check_insn(struct ir_function *fun) {
    // Check syntax
    // - Store uses alloc
    // - `ret` at the end of BB chains
}

void check_insn_operand(struct ir_insn *insn) {
    struct array      operands = get_operands(insn);
    struct ir_value **val;
    array_for(val, operands) {
        struct ir_value *v = *val;
        if (v->type == IR_VALUE_INSN) {
            // Check if the operand actually is used by this instruction
            struct ir_insn **pos2;
            int              found = 0;
            array_for(pos2, v->data.insn_d->users) {
                struct ir_insn *user = *pos2;
                if (user == insn) {
                    // Found the user
                    found = 1;
                    break;
                }
            }
            if (!found) {
                // Error!
                CRITICAL("Operand is not used by the instruction");
            }
        }
    }
    array_free(&operands);
}

// Check if the users are correct (only applicable to SSA IR form)
void check_users(struct ir_function *fun) {
    // Check FunctionCallArgument Instructions
    for (__u8 i = 0; i < MAX_FUNC_ARG; ++i) {
        struct ir_insn *insn = fun->function_arg[i];
        check_insn_users_use_insn(insn);
    }
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            // Check users of this instruction
            check_insn_users_use_insn(insn);
            // Check operands of this instruction
            check_insn_operand(insn);
        }
    }
}

void check_jumping(struct ir_function *fun) {
    // check if the jump statement is at the end of the BB
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        int jmp_exists = 0;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            if (is_jmp(insn)) {
                jmp_exists = 1;
                struct ir_insn *next_insn = list_next_entry(insn, list_ptr);
                if (next_insn != &bb->ir_insn_head) {
                    // Error
                    CRITICAL("Jump statement not at the end of a BB");
                } else {
                    // for conditional jumps, both BB1 and BB2 should be successors
                    if (is_jmp_cond(insn)) {
                        // get the two basic blocks that the conditional jump statement jumps to
                        struct ir_basic_block *bb1 = insn->bb1;
                        struct ir_basic_block *bb2 = insn->bb2;
                        // check if the two basic blocks are successors of the current BB
                        struct ir_basic_block **succ;
                        int ok1 = 0;
                        int ok2 = 0;
                        array_for(succ, bb->succs) {
                            struct ir_basic_block *succ_bb = *succ;
                            if (succ_bb == bb1) {
                                struct ir_basic_block *pred;
                                array_for(pred, bb1->preds) {
                                    struct ir_basic_block *pred_bb = *pred;
                                    if (pred_bb == bb) {
                                        ok1 = 1;
                                        break;
                                    }
                                }
                            }
                            if (succ_bb == bb2) {
                                struct ir_basic_block *pred;
                                array_for(pred, bb2->preds) {
                                    struct ir_basic_block *pred_bb = *pred;
                                    if (pred_bb == bb) {
                                        ok2 = 1;
                                        break;
                                    }
                                }
                            }
                        }
                        if (!ok1 || !ok2) {
                            // Error
                            CRITICAL("Conditional jump statement with operands that are not successors of the current BB");
                        }
                    } else {
                        // for unconditional jumps, there should be only one successor
                        if (bb->succs.num_elem != 1) {
                            // Error
                            CRITICAL("Unconditional jump statement with more than one successor");
                        } else {
                            // check if the jump operand is the only successor of BB
                            struct ir_basic_block *succ = bb->succs.data[0];
                            if (succ != insn->bb1) {
                                // Error
                                CRITICAL("ERR-Unconditional jump statement with a successor that is not the jump operand");
                            }

                            // check if the successor has the current BB as a predecessor
                            // struct ir_basic_block **succ;
                            // int found = 0;
                            // array_for(succ, bb->succs) {
                            //     struct ir_basic_block *succ_bb = *succ;
                            //     struct ir_basic_block **pred;
                            //     array_for(pred, succ_bb->preds) {
                            //         struct ir_basic_block *pred_bb = *pred;
                            //         if (pred_bb == bb) {
                            //             found = 1;
                            //             break;
                            //         }
                            //     }
                            //     if (found) {
                            //         break;
                            //     }
                            // }
                            // if (!found) {
                            //     // Error
                            //     CRITICAL("Unconditional jump statement with a successor that does not have the current BB as a predecessor");
                            // }
                        }
                    }
                }
            }
        }
        // if there is no jump statement, there should be only one successor
        if (!jmp_exists) {
            if (bb->succs.num_elem > 1) {
                // Error
                CRITICAL("No jump statement in BB but more than one successor");
            }
        }
    }
    
}

// Check if the PHI nodes are at the beginning of the BB
void check_phi(struct ir_function *fun) {
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb      = *pos;
        int                    all_phi = 1;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            if (insn->op == IR_INSN_PHI) {
                if (!all_phi) {
                    // Error!
                    CRITICAL("Phi node not at the beginning of a BB");
                }
            } else {
                all_phi = 0;
            }
        }
    }
}

// Check that the program is valid and able to be compiled
void prog_check(struct ir_function *fun) {
    check_phi(fun);
}
