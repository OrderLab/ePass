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

	err = epass_run(uopts, insns, index);

end:
	fclose(fp);
	return err;
}
