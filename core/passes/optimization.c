// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

static void remove_no_user_insn(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Remove all instructions that have no users, except for void instructions & calls
	bool changed = false;
	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (bpf_ir_is_void(insn) || insn->op == IR_INSN_CALL) {
				continue;
			}
			if (insn->users.num_elem == 0) {
				changed = true;
				bpf_ir_erase_insn(env, insn);
				CHECK_ERR();
			}
		}
	}
	if (changed) {
		remove_no_user_insn(env, fun);
	}
}

static void remove_unused_alloc(struct bpf_ir_env *env, struct ir_function *fun)
{
	// Remove all alloc instructions that have no users
	struct array alloc_insns;
	INIT_ARRAY(&alloc_insns, struct ir_insn *);

	struct ir_basic_block **pos;
	array_for(pos, fun->reachable_bbs)
	{
		struct ir_basic_block *bb = *pos;
		struct ir_insn *insn, *tmp;
		list_for_each_entry_safe(insn, tmp, &bb->ir_insn_head,
					 list_ptr) {
			if (insn->op == IR_INSN_ALLOC) {
				bpf_ir_array_push(env, &alloc_insns, &insn);
			}
		}
	}

	struct ir_insn **pos2;
	array_for(pos2, alloc_insns)
	{
		bool has_load = false;
		struct ir_insn *insn = *pos2;
		struct ir_insn **pos3;
		array_for(pos3, insn->users)
		{
			struct ir_insn *user = *pos3;
			if (user->op == IR_INSN_LOAD) {
				has_load = true;
				break;
			}
		}
		if (!has_load) {
			// Remove all its store
			array_for(pos3, insn->users)
			{
				struct ir_insn *user = *pos3;
				bpf_ir_erase_insn(env, user);
				CHECK_ERR();
			}
			// Remove itself
			bpf_ir_erase_insn(env, insn);
			CHECK_ERR();
		}
	}

	bpf_ir_array_free(&alloc_insns);
}

struct bpf_ir_optimization_opt {
	bool no_dead_elim;
	bool no_opt;
};

void bpf_ir_optimize_ir(struct bpf_ir_env *env, struct ir_function *fun,
			void *param)
{
	struct bpf_ir_optimization_opt *opt = param;

	if (opt && opt->no_opt) {
		PRINT_LOG(env, "skip optimization\n");
		return;
	}

	if (!(opt && opt->no_dead_elim)) {
		remove_no_user_insn(env, fun);
		CHECK_ERR();
	} else {
		PRINT_LOG(env, "skip remove_no_user_insn\n");
	}

	remove_unused_alloc(env, fun);
	CHECK_ERR();
}

static void get_opt(char *p, char **src)
{
	while (**src && **src != ' ') {
		*p = **src;
		p++;
		(*src)++;
	}
	*p = '\0';
}

#define GET_OPT(p, src)               \
	while (*src && *src != ' ') { \
		*p = *src;            \
		p++;                  \
		src++;                \
	}                             \
	*p = '\0';

#define NEXT_OPT(src)  \
	if (*src) {    \
		src++; \
	} else {       \
		break; \
	}

static int load_param(const char *opt, void **param)
{
	struct bpf_ir_optimization_opt ropt;
	ropt.no_dead_elim = false;
	ropt.no_opt = false;

	char mopt[30] = { 0 };
	const char *src = opt;
	while (*src) {
		char *p = mopt;
		GET_OPT(p, src);

		if (strcmp(mopt, "no_dead_elim") == 0) {
			ropt.no_dead_elim = true;
		}

		if (strcmp(mopt, "noopt") == 0) {
			ropt.no_opt = true;
		}

		NEXT_OPT(src);
	}

	*param = malloc_proto(sizeof(struct bpf_ir_optimization_opt));
	if (!*param) {
		return -ENOMEM;
	}
	*(struct bpf_ir_optimization_opt *)(*param) = ropt;
	return 0;
}

static void unload_param(void *param)
{
	free_proto(param);
}

const struct builtin_pass_cfg bpf_ir_kern_optimization_pass =
	DEF_BUILTIN_PASS_ENABLE_CFG("optimize_ir", load_param, unload_param);
