// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include "epasstool.h"

struct user_opts *uopts_g = NULL;

static int callback_fn(struct bpf_program *prog,
		       struct bpf_prog_load_opts *opts, long cookie)
{
	return epass_run(*uopts_g, bpf_program__insns(prog),
			 bpf_program__insn_cnt(prog));
}

int epass_readload(struct user_opts uopts)
{
	int err = 0;
	uopts_g = &uopts;
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

	// Register the callback
	struct libbpf_prog_handler_opts handler_opts;
	handler_opts.sz = sizeof(handler_opts);
	handler_opts.prog_attach_fn = NULL;
	handler_opts.prog_setup_fn = NULL;
	handler_opts.prog_prepare_load_fn = callback_fn;
	libbpf_register_prog_handler(bpf_program__section_name(prog),
				     bpf_program__get_type(prog),
				     bpf_program__expected_attach_type(prog),
				     &handler_opts);

	// Re-open the file to trigger the callback
	bpf_object__close(obj);
	obj = bpf_object__open(uopts.prog);
#ifdef EPASS_LIBBPF
	err = bpf_object__load(obj, 0, NULL, NULL);
#else
	err = bpf_object__load(obj);
#endif

	if (err) {
		fprintf(stderr, "Failed to load the file\n");
		goto end;
	} else {
		printf("File loaded successfully\n");
	}

end:
	bpf_object__close(obj);
	return err;
}
