// SPDX-License-Identifier: GPL-2.0-only
#include "bpf/libbpf.h"
#include <linux/bpf_ir.h>
#include <getopt.h>
#include "userspace.h"

// Userspace tool

int main(int argc, char **argv)
{
	enum {
		MODE_NONE,
		MODE_READ,
		MODE_READLOG,
		MODE_PRINT,
	} mode = MODE_NONE;
	struct user_opts uopts;
	static struct option long_options[] = {
		{ "mode", required_argument, NULL, 'm' },
		{ "gopt", required_argument, NULL, 0 },
		{ "popt", required_argument, NULL, 0 },
		{ "prog", required_argument, NULL, 'p' },
		{ "sec", required_argument, NULL, 's' },
		{ NULL, 0, NULL, 0 }
	};
	int ch = 0;
	int opt_index = 0;
	while ((ch = getopt_long(argc, argv, "m:p:s:", long_options,
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
				}
				break;
			case 'p':
				strcpy(uopts.prog, optarg);
				break;
			case 's':
				strcpy(uopts.sec, optarg);
				break;
			default:
				break;
			}
		}
	}

	if (mode == MODE_NONE) {
		return 1;
	}
}
