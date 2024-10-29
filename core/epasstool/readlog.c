// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include "epasstool.h"

int readlog(struct user_opts uopts)
{
	FILE *fp = NULL;
	char *program_name = uopts.prog;
	fp = fopen(program_name, "r");
	if (!fp) {
		return -1;
	}
	char line[256];
	struct bpf_insn *insns = malloc_proto(sizeof(struct bpf_insn) * 1000);
	size_t index = 0;
	while (fgets(line, sizeof(line), fp)) {
		int found = 0;
		while (line[found]) {
			if (line[found] == ':') {
				break;
			}
			found++;
		}
		if (!line[found]) {
			printf("No `:` found\n");
			return 1;
		}
		u64 s = strtoull(line + found + 1, NULL, 10);
		// printf("%llu\n", s);
		memcpy(&insns[index], &s, sizeof(struct bpf_insn));
		index++;
	}

	struct bpf_ir_env *env = bpf_ir_init_env(uopts.opts, insns, index);
	if (!env) {
		return 1;
	}
	int err = bpf_ir_init_opts(env, uopts.gopt, uopts.popt);
	if (err) {
		return err;
	}
	enable_builtin(env);
	bpf_ir_run(env);
	// bpf_ir_print_log_dbg(env);
	bpf_ir_free_opts(env);
	bpf_ir_free_env(env);

	fclose(fp);
	return 0;
}
