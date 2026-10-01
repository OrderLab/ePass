// SPDX-License-Identifier: GPL-2.0-only
/*
 * For each BPF object: load it with libbpf (run with LIBBPF_ENABLE_EPASS=1
 * LIBBPF_EPASS_KERNEL=1 LIBBPF_EPASS_GOPT=verbose=2) and a verifier log per
 * program, and report what in-kernel ePass did to each program, from the
 * ePass lines the kernel appends to the verifier log.
 */
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>

static char logs[16][1 << 20];

static int quiet(enum libbpf_print_level l, const char *f, va_list a) { return 0; }

int main(int argc, char **argv)
{
	int compiled = 0, original = 0, none = 0, failed_objs = 0;

	libbpf_set_print(quiet);
	for (int i = 1; i < argc; i++) {
		struct bpf_object *obj = bpf_object__open(argv[i]);
		struct bpf_program *p;
		int k = 0;

		if (!obj)
			continue;
		bpf_object__for_each_program(p, obj) {
			if (k == 16)
				break;
			logs[k][0] = 0;
			bpf_program__set_log_buf(p, logs[k], sizeof(logs[k]));
			bpf_program__set_log_level(p, 1);
			k++;
		}
		if (bpf_object__load(obj))
			failed_objs++;
		k = 0;
		bpf_object__for_each_program(p, obj) {
			if (k == 16)
				break;
			const char *l = logs[k++];
			const char *what = strstr(l, "instructions (isa") ? "compiled"
				: strstr(l, "loading the original") ? "original" : "none";
			if (!strcmp(what, "compiled"))
				compiled++;
			else if (!strcmp(what, "original"))
				original++;
			else
				none++;
			if (strcmp(what, "compiled")) {
				const char *e = strstr(l, "epass: ");
				printf("%s:%s: %s%s%.120s\n", argv[i], bpf_program__name(p), what,
				       e ? " -- " : "", e ? e : "");
			}
		}
		bpf_object__close(obj);
	}
	printf("ePass in kernel: %d programs compiled, %d kept original, %d without ePass log; %d objects failed to load\n",
	       compiled, original, none, failed_objs);
	return 0;
}
