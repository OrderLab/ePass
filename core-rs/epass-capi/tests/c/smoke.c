// SPDX-License-Identifier: GPL-2.0-only
/* C-side check of epass.h against libepass.a: struct layouts as C sees
 * them, struct bpf_insn compatibility, and one compilation. */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "epass.h"

/* As in <linux/bpf.h>. */
struct bpf_insn {
	uint8_t code;
	uint8_t dst_reg : 4;
	uint8_t src_reg : 4;
	int16_t off;
	int32_t imm;
};

#define CHECK(c)                                                    \
	do {                                                        \
		if (!(c)) {                                         \
			fprintf(stderr, "check failed: %s\n", #c); \
			return 1;                                   \
		}                                                   \
	} while (0)

int main(void)
{
	CHECK(sizeof(struct epass_insn) == sizeof(struct bpf_insn));
	CHECK(sizeof(struct epass_sig) == 4);
	CHECK(offsetof(struct epass_input, ir) == 16);
	CHECK(offsetof(struct epass_output, offsets) == 16);
	CHECK(offsetof(struct epass_output, host) == 40);
	CHECK(sizeof(struct epass_policy) == 40);

	/* r2 = *(u64 *)(r1 + 0); r3 = 5; r3 *= 3; r0 = r2; r0 += r3; exit */
	struct bpf_insn prog[] = {
		{ .code = 0x79, .dst_reg = 2, .src_reg = 1 },
		{ .code = 0xb7, .dst_reg = 3, .imm = 5 },
		{ .code = 0x27, .dst_reg = 3, .imm = 3 },
		{ .code = 0xbf, .dst_reg = 0, .src_reg = 2 },
		{ .code = 0x0f, .dst_reg = 0, .src_reg = 3 },
		{ .code = 0x95 },
	};
	const char *gopt = "verbose=2";
	struct epass_input in = {
		.insns = (const struct epass_insn *)prog,
		.insn_cnt = sizeof(prog) / sizeof(prog[0]),
		.gopt = gopt,
		.gopt_len = (epass_u32)strlen(gopt),
		.flags = EPASS_IN_REQUESTED,
	};
	struct epass_output out;
	int rc = epass_compile(epass_default_host(), NULL, NULL, &in, &out);
	printf("rc=%d insns=%u offsets=%u log=%s", rc, out.insn_cnt, out.offsets_cnt,
	       out.log ? out.log : "(none)\n");
	CHECK(rc == 0);
	CHECK(out.insn_cnt > 0 && out.insn_cnt <= in.insn_cnt);
	CHECK(out.offsets_cnt == in.insn_cnt + 1);
	CHECK(out.offsets[in.insn_cnt] == out.insn_cnt);
	/* The rewritten program still ends in exit and reads ctx through r1. */
	const struct bpf_insn *o = (const struct bpf_insn *)out.insns;
	CHECK(o[out.insn_cnt - 1].code == 0x95);
	CHECK(o[0].code == 0x79 && o[0].src_reg == 1);
	epass_output_free(&out);
	CHECK(out.insns == NULL && out.log == NULL);
	puts("smoke ok");
	return 0;
}
