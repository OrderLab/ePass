#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf_ir.h>
#include <string.h>

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

	printf("Loaded program of size %zu\n", index);
	struct bpf_ir_opts opts = {
		.debug = 1,
		.print_mode = BPF_IR_PRINT_BPF,
		.custom_pass_num = 0,
		.builtin_enable_pass_num = 0,
	};
	struct bpf_ir_env *env = bpf_ir_init_env(opts, insns, index);
	if (!env) {
		return 1;
	}
	bpf_ir_run(env);
	// bpf_ir_print_log_dbg(env);
	bpf_ir_free_env(env);

	fclose(fp);
	return 0;
}
