#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int print(const struct bpf_insn *insns, size_t len)
{
	for (__u32 i = 0; i < len; ++i) {
		const struct bpf_insn *insn = &insns[i];
		printf("insn[%d]: code=%x, dst_reg=%x, src_reg=%x, off=%x, imm=%x\n",
		       i, insn->code, insn->dst_reg, insn->src_reg, insn->off,
		       insn->imm);
		// __u64 data;
		// memcpy(&data, insn, sizeof(struct bpf_insn));
		// printf("insn[%d]: %llu\n", i, data);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc <= 1) {
		return -1;
	}
	FILE *fp = NULL;
	char *program_name = argv[1];
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

	print(insns, index);

	fclose(fp);
	return 0;
}
