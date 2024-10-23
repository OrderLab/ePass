// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

/* Initialize pass configuration for kernel component
 *
 * @param env: bpf_ir_env, must be already initialized
 * @param pass_opt: pass specific options
 * @param global_opt: global options
 *
 * Return: 0 on success, negative on error
 */
int bpf_ir_init_opts(struct bpf_ir_env *env, const char *pass_opt,
		     const char *global_opt)
{
	// Parse global options
	u32 len = 0;
	char opt[32];
	const char *p = global_opt;
	while (*p != '\0') {
		if (len >= 32) {
			return -EINVAL;
		}
		if (*p == ',') {
			// New option
			if (strcmp(opt, "force") == 0) {
			}
			len = 0;
			++p;
			continue;
		}
		opt[len] = *p;
		++p;
	}
	return 0;
}
