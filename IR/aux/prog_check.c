#include "array.h"
#include "bpf_ir.h"
#include "dbg.h"
#include "ir_insn.h"
#include "ir_helper.h"
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
            print_ir_insn_err(insn, "The instruction");
            print_ir_insn_err(user, "The user of that instruction");
            CRITICAL("User does not use the instruction");
        }
    }
}

void check_insn(struct ir_function *fun) {
    // Check syntax
    // Check value num
    // - Store uses alloc
    // - Load uses alloc
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;
        struct ir_insn        *insn;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            if (insn->op == IR_INSN_LOADRAW || insn->op == IR_INSN_ALLOC ||
                insn->op == IR_INSN_JA || insn->op == IR_INSN_PHI) {
                if (!(insn->value_num == 0)) {
                    print_ir_insn_err(insn, NULL);
                    CRITICAL("Instruction should have no value");
                }
            }

            if (insn->op == IR_INSN_STORERAW || insn->op == IR_INSN_LOAD ||
                insn->op == IR_INSN_RET || insn->op == IR_INSN_ASSIGN) {
                if (!(insn->value_num == 1)) {
                    print_ir_insn_err(insn, NULL);
                    CRITICAL("Instruction should have 1 value");
                }
            }

            if (insn->op == IR_INSN_STORE || (insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL) ||
                (insn->op >= IR_INSN_JEQ && insn->op < IR_INSN_PHI)) {
                if (!(insn->value_num == 2)) {
                    print_ir_insn_err(insn, NULL);
                    CRITICAL("Instruction should have 2 values");
                }
            }

            if (insn->op == IR_INSN_STORE || insn->op == IR_INSN_LOAD) {
                if (!(insn->values[0].type == IR_VALUE_INSN &&
                      insn->values[0].data.insn_d->op == IR_INSN_ALLOC)) {
                    print_ir_insn_err(insn, NULL);
                    CRITICAL("Value[0] should be an alloc instruction");
                }
            }
            
            // Check: users of alloc instructions must be STORE/LOAD
            if (insn->op == IR_INSN_ALLOC) {
                struct ir_insn **pos2;
                array_for(pos2, insn->users) {
                    struct ir_insn *user = *pos2;
                    if (user->op != IR_INSN_STORE && user->op != IR_INSN_LOAD) {
                        print_ir_insn_err(insn, NULL);
                        CRITICAL("Users of alloc instructions must be STORE/LOAD");
                    }
                }
            }

            if (insn->op >= IR_INSN_ADD && insn->op < IR_INSN_CALL) {
                // Binary ALU
                if (!(insn->alu == IR_ALU_64 || insn->alu == IR_ALU_32)) {
                    print_ir_insn_err(insn, NULL);
                    CRITICAL("Binary ALU type error!");
                }
            }

            // Check: JA should have only one valid bb
            if (insn->op == IR_INSN_JA) {
                if (insn->bb1 == NULL) {
                    print_ir_insn_err(insn, NULL);
                    CRITICAL("Unconditional jump instruction should have a valid bb");
                }
                if (insn->bb2 != NULL) {
                    print_ir_insn_err(insn, NULL);
                    CRITICAL("Unconditional jump instruction should have only one valid bb");
                }
            }
            // Check: JEQ, JGT, JGE, JLT, JLE, JNE should have 2 valid bbs
            if (insn->op >= IR_INSN_JEQ && insn->op <= IR_INSN_JNE) {
                if (insn->bb1 == NULL || insn->bb2 == NULL) {
                    print_ir_insn_err(insn, NULL);
                    CRITICAL("Conditional jump instruction should have 2 valid bbs");
                }
            }
        }
    }
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
                print_ir_insn_err(v->data.insn_d, "Operand defined here");
                print_ir_insn_err(insn, "Instruction that uses the operand");
                CRITICAL("Instruction not found in the operand's users");
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
    // Check if the jump instruction is at the end of the BB
    struct ir_basic_block **pos;
    array_for(pos, fun->reachable_bbs) {
        struct ir_basic_block *bb = *pos;

        // check if BB is a succ of its preds
        struct ir_basic_block **pred;
        array_for(pred, bb->preds) {
            struct ir_basic_block  *pred_bb = *pred;
            struct ir_basic_block **succ;
            int                     found = 0;
            array_for(succ, pred_bb->succs) {
                struct ir_basic_block *succ_bb = *succ;
                if (succ_bb == bb) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                // Error
                print_ir_bb_err(bb);
                CRITICAL("BB not a succ of its pred");
            }
        }

        struct ir_basic_block **succ;
        array_for(succ, bb->succs) {
            struct ir_basic_block  *succ_bb = *succ;
            struct ir_basic_block **p;
            int                     found = 0;
            array_for(p, succ_bb->preds) {
                struct ir_basic_block *sp = *p;
                if (sp == bb) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                // Error
                print_ir_bb_err(bb);
                CRITICAL("BB not a pred of its succ");
            }
        }

        struct ir_insn *insn;
        int             jmp_exists = 0;
        list_for_each_entry(insn, &bb->ir_insn_head, list_ptr) {
            if (is_jmp(insn)) {
                jmp_exists = 1;
                if (!is_last_insn(insn)) {
                    // Error

                    print_ir_insn_err(insn, NULL);
                    CRITICAL("Jump statement not at the end of a BB");
                } else {
                    if (insn->op == IR_INSN_RET) {
                        if (bb->succs.num_elem != 0) {
                            // Error

                            print_ir_insn_err(insn, NULL);
                            CRITICAL("successor exists even after return statement");
                        }
                        continue;
                    }
                    // For conditional jumps, both BB1 and BB2 should be successors
                    if (is_cond_jmp(insn)) {
                        // Get the two basic blocks that the conditional jump statement jumps to
                        struct ir_basic_block *bb1 = insn->bb1;
                        struct ir_basic_block *bb2 = insn->bb2;
                        // Check if the two basic blocks are successors of the current BB
                        if (bb->succs.num_elem != 2) {
                            CRITICAL("BB succs error");
                        }
                        if (*array_get(&bb->succs, 0, struct ir_basic_block *) != bb1 ||
                            *array_get(&bb->succs, 1, struct ir_basic_block *) != bb2) {
                            // Error
                            CRITICAL(
                                "Conditional jump statement with operands that are not successors "
                                "of the current BB");
                        }
                    } else {
                        // For unconditional jumps, there should be only one successor
                        if (bb->succs.num_elem != 1) {
                            // Error

                            print_ir_insn_err(insn, NULL);
                            CRITICAL("Unconditional jump statement with more than one successor");
                        }
                        // Check if the jump operand is the only successor of BB
                        if (*array_get(&bb->succs, 0, struct ir_basic_block *) != insn->bb1) {
                            // Error

                            print_ir_insn_err(insn, NULL);
                            CRITICAL("The jump operand is not the only successor of BB");
                        }
                    }
                }
            }
        }
        // If there is no jump instruction (means no ret), there should be one successor
        if (!jmp_exists) {
            if (bb->succs.num_elem != 1) {
                // Error
                print_ir_bb_err(bb);
                CRITICAL("Succ num error");
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
                    print_ir_insn_err(insn, NULL);
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
    print_ir_err_init(fun);

    check_insn(fun);
    check_phi(fun);
    check_users(fun);
    check_jumping(fun);
}
