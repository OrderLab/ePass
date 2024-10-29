// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

static int apply_pass_opt(struct bpf_ir_env *env, const char *opt)
{
	char pass_name[BPF_IR_MAX_PASS_NAME_SIZE];
	u32 pass_len = 0;
	char param[64];
	u32 len = 0;
	bool has_param = false;
	bool has_closed = false;
	const char *p = opt;
	while (*p != '\0') {
		if (len >= 64) {
			return -EINVAL;
		}
		if (*p == '(' && !has_param) {
			has_param = true;
			++p;
			continue;
		}
		if (has_param && *p == ')') {
			// End of parameter
			has_closed = true;
			break;
		}
		if (has_param) {
			param[len++] = *p;
		} else {
			pass_name[pass_len++] = *p;
		}
		++p;
	}
	if (has_param && !has_closed) {
		return -EINVAL;
	}
	pass_name[pass_len] = '\0';
	if (has_param) {
		param[len] = '\0';
	}
	bool found_pass = false;
	for (size_t i = 0; i < env->opts.builtin_pass_cfg_num; ++i) {
		if (strcmp(env->opts.builtin_pass_cfg[i].name, pass_name) ==
		    0) {
			found_pass = true;
			if (has_param &&
			    env->opts.builtin_pass_cfg[i].param_load) {
				int res =
					env->opts.builtin_pass_cfg[i].param_load(
						param,
						&env->opts.builtin_pass_cfg[i]
							 .param);
				if (res) {
					return res;
				}
			}
			env->opts.builtin_pass_cfg[i].enable_cfg = true;
			env->opts.builtin_pass_cfg[i].enable = false;
			break;
		}
	}
	if (!found_pass) {
		// Find in custom passes

		for (size_t i = 0; i < env->opts.custom_pass_num; ++i) {
			if (strcmp(env->opts.custom_passes[i].pass.name,
				   pass_name) == 0) {
				found_pass = true;
				if (has_param &&
				    env->opts.custom_passes[i].param_load) {
					int res = env->opts.custom_passes[i].param_load(
						param,
						&env->opts.custom_passes[i]
							 .param);
					if (res) {
						return res;
					}
				}
				// Custom passes, enabled at all time
				env->opts.custom_passes[i].pass.enabled = true;
				break;
			}
		}
	}
	return 0;
}

static int apply_global_opt(struct bpf_ir_env *env, const char *opt)
{
	if (strcmp(opt, "force") == 0) {
		env->opts.force = true;
	} else if (strcmp(opt, "enable_coalesce") == 0) {
		env->opts.enable_coalesce = true;
	} else if (strcmp(opt, "debug") == 0) {
		env->opts.debug = true;
	} else if (strcmp(opt, "print_bpf") == 0) {
		env->opts.print_mode = BPF_IR_PRINT_BPF;
	} else if (strcmp(opt, "print_dump") == 0) {
		env->opts.print_mode = BPF_IR_PRINT_DUMP;
	} else if (strcmp(opt, "print_detail") == 0) {
		env->opts.print_mode = BPF_IR_PRINT_DETAIL;
	} else if (strcmp(opt, "print_bpf_detail") == 0) {
		env->opts.print_mode = BPF_IR_PRINT_BPF_DETAIL;
	} else if (strncmp(opt, "verbose=", 8) == 0) {
		int res = 0;
		int err = parse_int(opt + 8, &res);
		if (err) {
			return err;
		}
		if (res < 0 || res > 10) {
			return -EINVAL;
		}
		env->opts.verbose = res;
	} else if (strncmp(opt, "maxit=", 6) == 0) {
		int res = 0;
		int err = parse_int(opt + 6, &res);
		if (err) {
			return err;
		}
		if (res < 0 || res > 15) {
			return -EINVAL;
		}
		env->opts.max_iteration = res;
	} else {
		return -EINVAL;
	}
	return 0;
}

// Check if a builtin pass is enabled (by cfg)
bool bpf_ir_builtin_pass_enabled(struct bpf_ir_env *env, const char *pass_name)
{
	for (size_t i = 0; i < env->opts.builtin_pass_cfg_num; ++i) {
		if (strcmp(env->opts.builtin_pass_cfg[i].name, pass_name) ==
		    0) {
			return env->opts.builtin_pass_cfg[i].enable_cfg;
		}
	}
	return false;
}

#define GET_OPT(p, src)               \
	while (*src && *src != ',') { \
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

/* Initialize pass configuration for kernel component
 *
 * @param env: bpf_ir_env, must be already initialized
 * @param global_opt: global options
 * @param pass_opt: pass specific options
 *
 * Return: 0 on success, negative on error
 */
int bpf_ir_init_opts(struct bpf_ir_env *env, const char *global_opt,
		     const char *pass_opt)
{
	if (!pass_opt || !global_opt) {
		return -EINVAL;
	}
	// Parse global options
	int err = 0;
	// const char *p = global_opt;
	char opt[64];
	const char *src = global_opt;
	while (*src) {
		char *p = opt;
		GET_OPT(p, src);
		// PRINT_DBG("Global opt: %s\n", opt);
		err = apply_global_opt(env, opt);
		if (err < 0) {
			return err;
		}

		NEXT_OPT(src);
	}

	src = pass_opt;
	while (*src) {
		char *p = opt;
		GET_OPT(p, src);
		// PRINT_DBG("Pass opt: %s\n", opt);
		err = apply_pass_opt(env, opt);
		if (err < 0) {
			return err;
		}

		NEXT_OPT(src);
	}
	return 0;
}

/* Free the option memory, mainly the `param` field generated. */
void bpf_ir_free_opts(struct bpf_ir_env *env)
{
	for (size_t i = 0; i < env->opts.builtin_pass_cfg_num; ++i) {
		if (env->opts.builtin_pass_cfg[i].param &&
		    env->opts.builtin_pass_cfg[i].param_unload) {
			env->opts.builtin_pass_cfg[i].param_unload(
				env->opts.builtin_pass_cfg[i].param);
			env->opts.builtin_pass_cfg[i].param = NULL;
		}
	}
	for (size_t i = 0; i < env->opts.custom_pass_num; ++i) {
		if (env->opts.custom_passes[i].param &&
		    env->opts.custom_passes[i].param_unload) {
			env->opts.custom_passes[i].param_unload(
				env->opts.custom_passes[i].param);
			env->opts.custom_passes[i].param = NULL;
		}
	}
}
