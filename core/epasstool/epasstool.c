// SPDX-License-Identifier: GPL-2.0-only
#include "epasstool.h"

// Userspace tool

#ifndef EPASS_VERSION
#define EPASS_VERSION "undefined"
#endif

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

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [options] <file>\n\n"
		"Commands:\n"
		"  read   \tRead (lift, transform and compile) the specified file\n"
		"  print  \tPrint the specified file\n\n"
		"Options:\n"
		"  --load       \tRead with loading mode\n"
		"  --pass-only, -P \tSkip compilation\n"
		"  --gopt <arg> \tSpecify global optimization option\n"
		"  --popt <arg> \tSpecify pass optimization option\n"
		"  --sec, -s <arg> \tSpecify ELF section manually\n\n"
		"Examples:\n"
		"  %s read a.o\n"
		"  %s read --gopt verbose=3 myfile.txt\n"
		"  %s print a.o\n",
		prog, prog, prog, prog);

	exit(1);
}

bool is_elf_file(const char *file)
{
	char magic[4];
	FILE *f = fopen(file, "rb");
	if (!f) {
		return false;
	}
	if (fread(magic, 1, 4, f) < 4) {
		fclose(f);
		return false; // Not an ELF file
	}
	fclose(f);
	return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' &&
	       magic[3] == 'F';
}

static struct user_opts parse_cli(int argc, char **argv)
{
	char *prog = argv[0];
	struct user_opts uopts = { 0 };
	uopts.gopt[0] = 0;
	uopts.popt[0] = 0;
	uopts.prog[0] = 0;
	uopts.no_compile = false;
	uopts.auto_sec = true;
	if (argc < 2) {
		usage(prog);
	}
	argc--;
	argv++;
	if (strcmp(*argv, "read") == 0) {
		argc--;
		argv++;
		uopts.mode = MODE_READ;
		while (argc > 0) {
			if (strcmp(*argv, "--load") == 0) {
				uopts.mode = MODE_READLOAD;
			} else if (strcmp(*argv, "--pass-only") == 0 ||
				   strcmp(*argv, "-P") == 0) {
				uopts.no_compile = true;
			} else if (strcmp(*argv, "--gopt") == 0) {
				if (argc < 2) {
					usage(prog);
				}
				argc--;
				argv++;
				strcpy(uopts.gopt, *argv);
			} else if (strcmp(*argv, "--popt") == 0) {
				if (argc < 2) {
					usage(prog);
				}
				argc--;
				argv++;
				strcpy(uopts.popt, *argv);
			} else if (strcmp(*argv, "--sec") == 0 ||
				   strcmp(*argv, "-s") == 0) {
				if (argc < 2) {
					usage(prog);
				}
				argc--;
				argv++;
				uopts.auto_sec = false;
				strcpy(uopts.sec, *argv);
			} else {
				// File
				if (uopts.prog[0] == 0) {
					strcpy(uopts.prog, *argv);
				} else {
					usage(prog);
				}
			}
			argc--;
			argv++;
		}
		if (uopts.prog[0] == 0) {
			usage(prog);
		}
	} else if (strcmp(*argv, "print") == 0) {
		argc--;
		argv++;
		uopts.mode = MODE_PRINT;
		while (argc > 0) {
			if (strcmp(*argv, "--gopt") == 0) {
				if (argc < 2) {
					usage(prog);
				}
				argc--;
				argv++;
				strcpy(uopts.gopt, *argv);
			} else if (strcmp(*argv, "--popt") == 0) {
				if (argc < 2) {
					usage(prog);
				}
				argc--;
				argv++;
				strcpy(uopts.popt, *argv);
			} else {
				// File
				if (uopts.prog[0] == 0) {
					strcpy(uopts.prog, *argv);
				} else {
					usage(prog);
				}
			}
			argc--;
			argv++;
		}
		if (uopts.prog[0] == 0) {
			usage(prog);
		}
	} else {
		usage(prog);
	}

	return uopts;
}

int main(int argc, char **argv)
{
	struct user_opts uopts = parse_cli(argc, argv);
	bool is_elf = is_elf_file(uopts.prog);
	if (uopts.mode == MODE_PRINT) {
		return is_elf ? epass_print(uopts) : epass_printlog(uopts);
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

	if (uopts.mode == MODE_READ) {
		return is_elf ? epass_read(uopts) : epass_readlog(uopts);
	}

	if (uopts.mode == MODE_READLOAD) {
		return epass_readload(uopts);
	}

	return 0;
}
