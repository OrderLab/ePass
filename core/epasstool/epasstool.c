// SPDX-License-Identifier: GPL-2.0-only
#include <getopt.h>
#include "epasstool.h"

// Userspace tool

struct bpf_ir_opts common_opts;

// Enable all builtin passes specified by enable_cfg
void enable_builtin(struct bpf_ir_env *env)
{
	for (size_t i = 0; i < env->opts.builtin_pass_cfg_num; ++i) {
		if (env->opts.builtin_pass_cfg[i].enable_cfg) {
			env->opts.builtin_pass_cfg[i].enable = true;
		}
	}
}

static void usage(char *prog)
{
	printf("Usage: %s --mode <mode> --prog <prog> [--sec <sec>] "
	       "[--gopt <gopt>] [--popt <popt>]\n",
	       prog);
	printf("Modes:\n");
	printf("  read: Run ePass from object file\n");
	printf("  readload: Run ePass from object file and load it with modified bytecode\n");
	printf("  readlog: Run ePass from log\n");
	printf("  print: Print BPF program\n");
	printf("  printlog: Print BPF program from log\n");

	exit(1);
}

int main(int argc, char **argv)
{
	enum {
		MODE_NONE,
		MODE_READ,
		MODE_READLOAD,
		MODE_READLOG,
		MODE_PRINT,
		MODE_PRINT_LOG,
	} mode = MODE_NONE;
	struct user_opts uopts;
	uopts.gopt[0] = 0;
	uopts.popt[0] = 0;
	static struct option long_options[] = {
		{ "mode", required_argument, NULL, 'm' },
		{ "gopt", required_argument, NULL, 0 },
		{ "popt", required_argument, NULL, 0 },
		{ "prog", required_argument, NULL, 'p' },
		{ "sec", required_argument, NULL, 's' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	int ch = 0;
	int opt_index = 0;
	while ((ch = getopt_long(argc, argv, "m:p:s:h", long_options,
				 &opt_index)) != -1) {
		if (ch == 0) {
			// printf("option %s\n", long_options[opt_index].name);
			if (strcmp(long_options[opt_index].name, "gopt") == 0) {
				strcpy(uopts.gopt, optarg);
			} else if (strcmp(long_options[opt_index].name,
					  "popt") == 0) {
				strcpy(uopts.popt, optarg);
			}
		} else {
			switch (ch) {
			case 'm':
				if (strcmp(optarg, "read") == 0) {
					mode = MODE_READ;
				} else if (strcmp(optarg, "readlog") == 0) {
					mode = MODE_READLOG;
				} else if (strcmp(optarg, "print") == 0) {
					mode = MODE_PRINT;
				} else if (strcmp(optarg, "readload") == 0) {
					mode = MODE_READLOAD;
				} else if (strcmp(optarg, "printlog") == 0) {
					mode = MODE_PRINT_LOG;
				}
				break;
			case 'p':
				strcpy(uopts.prog, optarg);
				break;
			case 's':
				strcpy(uopts.sec, optarg);
				break;
			case 'h':
				usage(argv[0]);
				return 0;
				break;
			default:
				break;
			}
		}
	}

	if (mode == MODE_NONE) {
		printf("Mode not specified\n");
		usage(argv[0]);
	}

	if (mode == MODE_PRINT_LOG) {
		return printlog(uopts);
	}
	if (mode == MODE_PRINT) {
		return print(uopts);
	}

	// Initialize common options
	common_opts = bpf_ir_default_opts();
	struct builtin_pass_cfg passes[] = {
		bpf_ir_kern_add_counter_pass,
		bpf_ir_kern_optimization_pass,
		bpf_ir_kern_msan,
	};
	struct custom_pass_cfg custom_passes[] = {
		DEF_CUSTOM_PASS(DEF_FUNC_PASS(test_pass1, "test_pass1", false),
				NULL, NULL, NULL),
	};
	struct bpf_ir_opts opts = bpf_ir_default_opts();
	opts.custom_pass_num = sizeof(custom_passes) / sizeof(custom_passes[0]);
	opts.custom_passes = custom_passes;
	opts.builtin_pass_cfg_num = sizeof(passes) / sizeof(passes[0]);
	opts.builtin_pass_cfg = passes;

	uopts.opts = opts;

	if (mode == MODE_READLOG) {
		return readlog(uopts);
	}
	if (mode == MODE_READ) {
		return read(uopts);
	}
	if (mode == MODE_READLOAD) {
		return readload(uopts);
	}

	return 0;
}
