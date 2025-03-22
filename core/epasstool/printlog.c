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
		PRINT_LOG_DEBUG(env, "[%zu] ", i);
		bpf_ir_print_bpf_insn(env, insn);
	}
}

int epass_printlog(struct user_opts uopts)
{
	int err = 0;
	FILE *fp = NULL;
	char *program_name = uopts.prog;
	fp = fopen(program_name, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open the file.\n");
		return -1;
	}
	char line[256];
	struct bpf_insn *insns = malloc(sizeof(struct bpf_insn) * 1000);
	size_t index = 0;
	while (fgets(line, sizeof(line), fp)) {
		__u64 s = strtoull(line, NULL, 10);
		if (line[0] == '\n') {
			break;
		}
		memcpy(&insns[index], &s, sizeof(struct bpf_insn));
		index++;
	}

	printf("Loaded program of size %zu\n", index);

	struct bpf_ir_opts opts = bpf_ir_default_opts();
	opts.verbose = 3;
	struct bpf_ir_env *env = bpf_ir_init_env(opts, insns, index);
	if (!env) {
		err = -1;
		goto end;
	}
	print_bpf_prog(env, insns, index);
	// bpf_ir_print_log_dbg(env);
	bpf_ir_free_env(env);
end:
	free(insns);

	fclose(fp);
	return err;
}
