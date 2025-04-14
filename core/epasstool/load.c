// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include "epasstool.h"

int epass_load(struct user_opts uopts)
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

	err = bpf_object__load(obj);

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
