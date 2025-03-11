// SPDX-License-Identifier: GPL-2.0-only
#include <getopt.h>
#include "epasstool.h"

// Userspace tool

static const struct function_pass pre_passes_def[] = {
	DEF_FUNC_PASS(remove_trivial_phi, "remove_trivial_phi", true),
};

static struct function_pass post_passes_def[] = {
	DEF_FUNC_PASS(bpf_ir_div_by_zero, "div_by_zero", false),
	DEF_FUNC_PASS(msan, "msan", false),
	DEF_FUNC_PASS(insn_counter, "insn_counter", false),
	/* CG Preparation Passes */
	DEF_NON_OVERRIDE_FUNC_PASS(translate_throw, "translate_throw"),
	DEF_FUNC_PASS(bpf_ir_optimize_code_compaction, "optimize_compaction",
		      false),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_optimize_ir, "optimize_ir"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_cg_change_fun_arg, "change_fun_arg"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_cg_change_call_pre_cg, "change_call"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpf_ir_cg_add_stack_offset_pre_cg,
				   "add_stack_offset"),
	DEF_NON_OVERRIDE_FUNC_PASS(bpr_ir_cg_to_cssa, "to_cssa"),
};

const struct function_pass *pre_passes = pre_passes_def;
const struct function_pass *post_passes = post_passes_def;

const size_t post_passes_cnt =
	sizeof(post_passes_def) / sizeof(post_passes_def[0]);
const size_t pre_passes_cnt =
	sizeof(pre_passes_def) / sizeof(pre_passes_def[0]);

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
	       "[--gopt <gopt>] [--popt <popt>] --pass-only\n",
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
	uopts.prog[0] = 0;
	uopts.no_compile = false;
	uopts.auto_sec = true;
	static struct option long_options[] = {
		{ "mode", required_argument, NULL, 'm' },
		{ "gopt", required_argument, NULL, 0 },
		{ "popt", required_argument, NULL, 0 },
		{ "prog", required_argument, NULL, 'p' },
		{ "sec", required_argument, NULL, 's' },
		{ "help", no_argument, NULL, 'h' },
		{ "pass-only", no_argument, NULL, 0 },
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
			} else if (strcmp(long_options[opt_index].name,
					  "pass-only") == 0) {
				uopts.no_compile = true;
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
				uopts.auto_sec = false;
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
	if (uopts.prog[0] == 0) {
		printf("Program not specified\n");
		usage(argv[0]);
	}

	// Initialize common options
	common_opts = bpf_ir_default_opts();
	struct builtin_pass_cfg passes[] = {
		bpf_ir_kern_insn_counter_pass,
		bpf_ir_kern_optimization_pass,
		bpf_ir_kern_compaction_pass,
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
