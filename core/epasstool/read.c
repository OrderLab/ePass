// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include "epasstool.h"
#include <unistd.h>
#include <sys/wait.h>

int epass_run(struct user_opts uopts, const struct bpf_insn *insn, size_t sz)
{
	struct bpf_ir_env *env = bpf_ir_init_env(uopts.opts, insn, sz);
	if (!env) {
		return 1;
	}
	int err = bpf_ir_init_opts(env, uopts.gopt, uopts.popt);
	if (err) {
		bpf_ir_free_env(env);
		return err;
	}
	enable_builtin(env);
	u64 starttime = get_cur_time_ns();
	if (uopts.no_compile) {
		struct ir_function *fun =
			bpf_ir_lift(env, env->insns, env->insn_cnt);
		CHECK_ERR(0);
		bpf_ir_run(env, fun);
		bpf_ir_free_function(fun);
	} else {
		bpf_ir_autorun(env);
	}
	u64 tot = get_cur_time_ns() - starttime;

	if (env->err) {
		err = env->err;
		goto end;
	}

	printf("ePass finished in %lluns\n", tot);
	printf("lift %lluns\trun %lluns\tcompile %lluns\tsum %lluns\n",
	       env->lift_time, env->run_time, env->cg_time,
	       env->lift_time + env->run_time + env->cg_time);
	printf("program size: %zu->%zu\n", sz, env->insn_cnt);

	if (uopts.prog_out[0]) {
		if (uopts.output_format == OUTPUT_SEC_ONLY) {
			// Write the program to a file
			FILE *f = fopen(uopts.prog_out, "wb");
			if (!f) {
				fprintf(stderr,
					"Failed to open the output file\n");
				err = 1;
				goto end;
			}
			fwrite(env->insns, sizeof(struct bpf_insn),
			       env->insn_cnt, f);
			fclose(f);
		}

		if (uopts.output_format == OUTPUT_ELF) {
			FILE *f = fopen("/tmp/epass_tmp", "wb");
			if (!f) {
				fprintf(stderr,
					"Failed to open the output file\n");
				err = 1;
				goto end;
			}
			fwrite(env->insns, sizeof(struct bpf_insn),
			       env->insn_cnt, f);
			fclose(f);
			if (err) {
				fprintf(stderr,
					"Failed to generate the file\n");
				err = 1;
				goto end;
			}
			// Call objcopy
			int childpid;
			if ((childpid = fork()) == -1) {
				perror("Can't fork");
				err = 1;
				goto end;
			} else if (childpid == 0) {
				// Child
				char default_path[] = "/usr/bin/llvm-objcopy";
				char *path = getenv("OBJCOPY");
				if (path == NULL) {
					path = default_path;
				}
				char opts[30];
				sprintf(opts, "%s=%s", uopts.sec,
					"/tmp/epass_tmp");
				execl(path, "llvm-objcopy", "--update-section",
				      opts, uopts.prog, uopts.prog_out,
				      (char *)0);
				fprintf(stderr, "Failed to exec\n");
				err = 1;
				goto end;
			} else {
				wait(NULL);
			}
		}
	}

end:
	bpf_ir_free_opts(env);
	bpf_ir_free_env(env);
	return err;
}

int epass_read(struct user_opts uopts)
{
	int err = 0;
	struct bpf_object *obj = bpf_object__open(uopts.prog);
	if (!obj) {
		fprintf(stderr, "Failed to open the file.\n");
		return 1;
	}
	struct bpf_program *prog = NULL;
	if (uopts.auto_sec) {
		prog = bpf_object__next_program(obj, NULL);
		strcpy(uopts.sec, bpf_program__section_name(prog));
	} else {
		prog = bpf_object__find_program_by_name(obj, uopts.sec);
	}

	if (!prog) {
		fprintf(stderr, "Program not found\n");
		err = 1;
		goto end;
	}
	size_t sz = bpf_program__insn_cnt(prog);
	const struct bpf_insn *insn = bpf_program__insns(prog);

	err = epass_run(uopts, insn, sz);

end:
	bpf_object__close(obj);
	return err;
}
