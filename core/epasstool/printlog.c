// SPDX-License-Identifier: GPL-2.0-only
#include "epasstool.h"

static void print_bpf_prog(struct bpf_ir_env *env, const struct bpf_insn *insns,
			   size_t len)
{
	for (size_t i = 0; i < len; ++i) {
		const struct bpf_insn *insn = &insns[i];
		if (insn->code == 0) {
			continue;
		}
		PRINT_LOG(env, "[%zu] ", i);
		bpf_ir_print_bpf_insn(env, insn);
	}
}

int printlog(struct user_opts uopts)
{
	FILE *fp = NULL;
	char *program_name = uopts.prog;
	fp = fopen(program_name, "r");
	if (!fp) {
		return -1;
	}
	char line[256];
	struct bpf_insn *insns = malloc(sizeof(struct bpf_insn) * 1000);
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
		__u64 s = strtoull(line + found + 1, NULL, 10);
		// printf("%llu\n", s);
		memcpy(&insns[index], &s, sizeof(struct bpf_insn));
		index++;
	}

	printf("Loaded program of size %zu\n", index);

	struct bpf_ir_opts opts = {
		.debug = true,
		.print_mode = BPF_IR_PRINT_BPF,
		.custom_pass_num = 0,
		.builtin_pass_cfg_num = 0,
	};
	struct bpf_ir_env *env = bpf_ir_init_env(opts, insns, index);
	if (!env) {
		return 1;
	}
	print_bpf_prog(env, insns, index);
	bpf_ir_print_log_dbg(env);
	bpf_ir_free_env(env);
	free(insns);

	fclose(fp);
	return 0;
}
