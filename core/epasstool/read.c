// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include "epasstool.h"
#include <unistd.h>
#include <sys/wait.h>

static void print_bpf_prog_dump(FILE *fp, const struct bpf_insn *insns,
				size_t len)
{
	for (u32 i = 0; i < len; ++i) {
		const struct bpf_insn *insn = &insns[i];
		__u64 data;
		memcpy(&data, insn, sizeof(struct bpf_insn));
		fprintf(fp, "%llu\n", data);
	}
}

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
	PRINT_LOG_DEBUG(env, "Running ePass on section %s\n", uopts.sec);
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

	PRINT_LOG_DEBUG(env, "ePass finished in %lluns\n", tot);
	PRINT_LOG_DEBUG(env,
			"lift %lluns\trun %lluns\tcompile %lluns\tsum %lluns\n",
			env->lift_time, env->run_time, env->cg_time,
			env->lift_time + env->run_time + env->cg_time);
	PRINT_LOG_DEBUG(env, "program size: %zu->%zu\n", sz, env->insn_cnt);

	if (uopts.bpfprog) {
		err = bpf_program__set_insns(uopts.bpfprog, env->insns,
					     env->insn_cnt);
	}

	if (uopts.prog_out[0]) {
		FILE *f = fopen(uopts.prog_out, "wb");
		if (!f) {
			fprintf(stderr, "Failed to open the output file\n");
			err = 1;
			goto end;
		}
		if (uopts.output_format == OUTPUT_SEC_ONLY) {
			// Write the program to a file
			fwrite(env->insns, sizeof(struct bpf_insn),
			       env->insn_cnt, f);
		}
		if (uopts.output_format == OUTPUT_LOG) {
			print_bpf_prog_dump(f, env->insns, env->insn_cnt);
		}
		fclose(f);
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
