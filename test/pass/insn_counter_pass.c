static void add_counter_to_bb() {
    struct ir_insn *last = bpf_ir_get_last_insn(bb);
    if (!last || !bpf_ir_is_jmp(last)) {
        struct ir_insn *load_insn =
            bpf_ir_create_load_insn_bb(env, bb, bpf_ir_value_insn(alloc_insn), INSERT_BACK);
        struct ir_value cv    = bpf_ir_value_const32(-1);
        cv.builtin_const      = IR_BUILTIN_BB_INSN_CRITICAL_CNT;
        struct ir_insn *added = bpf_ir_create_bin_insn(env, load_insn, bpf_ir_value_insn(load_insn),                                                       cv, IR_INSN_ADD, IR_ALU_64, INSERT_BACK);
        struct ir_insn *store_back =            bpf_ir_create_store_insn(env, added, alloc_insn, bpf_ir_value_insn(added), INSERT_BACK);
        struct ir_basic_block **succ   = bpf_ir_array_get_void(&bb->succs, 0);
        struct ir_basic_block  *err_bb = bpf_ir_create_bb(env, fun);
        bpf_ir_create_throw_insn_bb(env, err_bb, INSERT_BACK);
        bpf_ir_create_jbin_insn(env, store_back, bpf_ir_value_insn(added),                                bpf_ir_value_const32(opt.counter_limit), *succ, err_bb, IR_INSN_JGT,                                IR_ALU_64, INSERT_BACK);
        bpf_ir_connect_bb(env, bb, err_bb);
        return;
    }
    struct ir_insn *load_insn =        bpf_ir_create_load_insn(env, last, bpf_ir_value_insn(alloc_insn), INSERT_FRONT);
    struct ir_value cv    = bpf_ir_value_const32(-1);
    cv.builtin_const      = IR_BUILTIN_BB_INSN_CRITICAL_CNT;
    struct ir_insn *added = bpf_ir_create_bin_insn(env, load_insn, bpf_ir_value_insn(load_insn), cv,                                                   IR_INSN_ADD, IR_ALU_64, INSERT_BACK);
    struct ir_insn *store_back =        bpf_ir_create_store_insn(env, added, alloc_insn, bpf_ir_value_insn(added), INSERT_BACK);
    struct ir_basic_block *new_bb, *err_bb;
    bpf_ir_bb_create_error_block(env, fun, store_back, INSERT_BACK, &err_bb, &new_bb);
    bpf_ir_create_jbin_insn(env, store_back, bpf_ir_value_insn(added),                            bpf_ir_value_const32(opt.counter_limit), new_bb, err_bb, IR_INSN_JGT,IR_ALU_64, INSERT_BACK);
}
void insn_counter(struct bpf_ir_env *env, struct ir_function *fun, void *param) {
    struct bpf_ir_counter_opt opt;
    opt.counter_limit = 1000000;
    opt.accurate      = false;
    if (param) {
        opt = *(struct bpf_ir_counter_opt *)param;
    }
    struct ir_basic_block *entry = fun->entry;
    struct ir_insn        *alloc_insn =        bpf_ir_create_alloc_insn_bb(env, entry, IR_VR_TYPE_32, INSERT_FRONT);
    bpf_ir_create_store_insn(env, alloc_insn, alloc_insn, bpf_ir_value_const32(0), INSERT_BACK);
    struct ir_basic_block **pos;
    if (opt.accurate) {
        struct array critical_bbs;
        INIT_ARRAY(&critical_bbs, struct ir_basic_block *);
        array_for(pos, fun->reachable_bbs) {
            struct ir_basic_block *bb = *pos;
            if (en_pred_num(fun, bb) > 1) {
                struct ir_basic_block **pos2;
                array_for(pos2, bb->preds) {
                    struct ir_basic_block *pred = *pos2;
                    if (pred->flag & IR_BB_HAS_COUNTER) {
                        continue;
                    }
                    pred->flag |= IR_BB_HAS_COUNTER;
                    bpf_ir_array_push(env, &critical_bbs, &pred);
                }
            }
        }
        array_for(pos, critical_bbs) {
            struct ir_basic_block *bb = *pos;
            add_counter_to_bb(env, bb, fun, opt, alloc_insn);
        }
        bpf_ir_array_free(&critical_bbs);
    } else {
        array_for(pos, fun->reachable_bbs) {
            struct ir_basic_block *bb = *pos;
            if (bb->preds.num_elem <= 1) {
                continue;
            }
            add_counter_to_bb(env, bb, fun, opt, alloc_insn);
        }
    }
}

static int load_param(const char *opt, void **param) {
    struct bpf_ir_counter_opt res;
    res.counter_limit = 1000000;
    res.accurate      = false;
    char        mopt[30] = {0};
    const char *src      = opt;
    while (*src) {
        char *p = mopt;
        GET_OPT(p, src);
        if (strcmp(mopt, "accurate") == 0) {
            res.accurate = true;
        }
        if (strncmp(mopt, "limit=", 6) == 0) {
            int err = parse_int(mopt + 6, &res.counter_limit);
            if (err) {
                return err;
            }
        }
        NEXT_OPT(src);
    }
    if (res.counter_limit > 1000000) {  // Could be configurable
        return -EINVAL;
    }
    *param = malloc_proto(sizeof(struct bpf_ir_counter_opt));
    if (!*param) {
        return -ENOMEM;
    }
    *(struct bpf_ir_counter_opt *)(*param) = res;
    return 0;
}
static void unload_param(void *param) {
    free_proto(param);
}
const struct builtin_pass_cfg bpf_ir_kern_insn_counter_pass =     DEF_BUILTIN_PASS_CFG("insn_counter", load_param, unload_param);
