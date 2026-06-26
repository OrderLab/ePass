// SPDX-License-Identifier: GPL-2.0-only

#include "epasstool.h"

int epass_readlog(struct user_opts uopts)
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
	struct array insns_array;
	struct bpf_ir_env tenv; // tmp
	INIT_ARRAY(&insns_array, struct bpf_insn);
	// struct bpf_insn *insns = malloc_proto(sizeof(struct bpf_insn) * 5000);
	size_t index = 0;
	while (fgets(line, sizeof(line), fp)) {
		u64 s = strtoull(line, NULL, 10);
		if (line[0] == '\n') {
			break;
		}
		struct bpf_insn tmp;
		memcpy(&tmp, &s, sizeof(struct bpf_insn));
		bpf_ir_array_push(&tenv, &insns_array, &tmp);
		index++;
	}

	err = epass_run(uopts, insns_array.data, index);

end:
	bpf_ir_array_free(&insns_array);

	fclose(fp);
	return err;
}
