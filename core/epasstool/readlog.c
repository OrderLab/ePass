// SPDX-License-Identifier: GPL-2.0-only

#include "epasstool.h"

int readlog(struct user_opts uopts)
{
	fprintf(stderr,
		"Warning: readlog command is only for testing usage.\n");
	int err = 0;
	FILE *fp = NULL;
	char *program_name = uopts.prog;
	fp = fopen(program_name, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open the file.\n");
		return 1;
	}
	char line[256];
	struct bpf_insn *insns = malloc_proto(sizeof(struct bpf_insn) * 5000);
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
			err = 1;
			goto end;
		}
		u64 s = strtoull(line + found + 1, NULL, 10);
		// printf("%llu\n", s);
		memcpy(&insns[index], &s, sizeof(struct bpf_insn));
		index++;
	}

	struct bpf_ir_env *env = bpf_ir_init_env(uopts.opts, insns, index);
	if (!env) {
		err = 1;
		goto end;
	}
	err = bpf_ir_init_opts(env, uopts.gopt, uopts.popt);
	if (err) {
		goto end;
	}
	enable_builtin(env);
	u64 starttime = get_cur_time_ns();
	bpf_ir_autorun(env);
	if (env->err) {
		err = env->err;
		goto end;
	}
	u64 tot = get_cur_time_ns() - starttime;

	printf("ePass finished in %lluns\n", tot);
	printf("lift %lluns\trun %lluns\tcompile %lluns\tsum %lluns\n",
	       env->lift_time, env->run_time, env->cg_time,
	       env->lift_time + env->run_time + env->cg_time);
	printf("program size: %zu->%zu\n", index, env->insn_cnt);

	bpf_ir_free_opts(env);
	bpf_ir_free_env(env);

end:
	fclose(fp);
	return err;
}
