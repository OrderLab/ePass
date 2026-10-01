// SPDX-License-Identifier: GPL-2.0-only
/*
 * In-VM selftest for the ePass kernel integration (run as root on a kernel
 * built with CONFIG_BPF_EPASS). Uses raw bpf() calls with the epass_*
 * fields of BPF_PROG_LOAD and links libepass.a to compile the same programs
 * in userspace:
 *
 *   kernel == userspace: xlated(load P with ePass in the kernel) equals
 *   xlated(load the userspace ePass output of P without ePass). Both go
 *   through the same verifier rewrites, so they agree exactly when the two
 *   ePass outputs are byte-identical.
 *
 * Also: IR input, option errors, fail-open, and the administrator policy
 * (kernel.bpf_epass_policy).
 *
 *   epass_selftest <dir with p1.blob>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "epass.h"

#define POLICY "/proc/sys/kernel/bpf_epass_policy"
#define MAXI 4096

static int failures, passes;

#define CHECK(cond, ...)                                     \
	do {                                                 \
		if (cond) {                                  \
			passes++;                            \
		} else {                                     \
			failures++;                          \
			printf("FAIL %s:%d: ", __func__, __LINE__); \
			printf(__VA_ARGS__);                 \
			printf("\n");                        \
		}                                            \
	} while (0)

#define I(c, d, s, o, i) ((struct bpf_insn){ .code = (c), .dst_reg = (d), .src_reg = (s), .off = (o), .imm = (i) })

/* r0 = prandom(); r2 = 5; r3 = 7; r2 *= r3; spill/reload; r0 += r2;
 * if r0 > 1000 goto +1; r0 = 0; exit   (const_prop folds r2 = 35) */
static const struct bpf_insn p1[] = {
	I(0x85, 0, 0, 0, 7),       /* call bpf_get_prandom_u32 */
	I(0xb7, 2, 0, 0, 5),       /* r2 = 5 */
	I(0xb7, 3, 0, 0, 7),       /* r3 = 7 */
	I(0x2f, 2, 3, 0, 0),       /* r2 *= r3 */
	I(0x7b, 10, 2, -8, 0),     /* *(u64 *)(r10 -8) = r2 */
	I(0x79, 4, 10, -8, 0),     /* r4 = *(u64 *)(r10 -8) */
	I(0x0f, 0, 4, 0, 0),       /* r0 += r4 */
	I(0x25, 0, 0, 1, 1000),    /* if r0 > 1000 goto +1 */
	I(0xb7, 0, 0, 0, 0),       /* r0 = 0 */
	I(0x95, 0, 0, 0, 0),       /* exit */
};

/* A counted loop: r0 = sum(1..10) through a phi on the back edge. */
static const struct bpf_insn p2[] = {
	I(0xb7, 0, 0, 0, 0),
	I(0xb7, 1, 0, 0, 10),
	I(0x0f, 0, 1, 0, 0),       /* r0 += r1 */
	I(0x07, 1, 0, 0, -1),      /* r1 -= 1 */
	I(0x55, 1, 0, -3, 0),      /* if r1 != 0 goto -3 */
	I(0x95, 0, 0, 0, 0),
};

/* bpf-to-bpf call: ePass does not support it yet (fails open). */
static const struct bpf_insn p3[] = {
	I(0x85, 0, 1, 0, 1),       /* call pc+1 */
	I(0x95, 0, 0, 0, 0),
	I(0xb7, 0, 0, 0, 0),
	I(0x95, 0, 0, 0, 0),
};

struct load {
	const struct bpf_insn *insns;
	unsigned int cnt;
	const void *ir;
	unsigned int ir_len;
	const char *gopt, *popt;
	unsigned int flags;
	char *log;
	unsigned int log_size;
};

static int sys_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int load(const struct load *l)
{
	union bpf_attr a;
	int fd;

	memset(&a, 0, sizeof(a));
	a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	a.insns = (uintptr_t)l->insns;
	a.insn_cnt = l->cnt;
	a.license = (uintptr_t)"GPL";
	a.prog_flags = l->flags;
	a.epass_gopt = (uintptr_t)l->gopt;
	a.epass_gopt_len = l->gopt ? strlen(l->gopt) : 0;
	a.epass_popt = (uintptr_t)l->popt;
	a.epass_popt_len = l->popt ? strlen(l->popt) : 0;
	a.epass_ir = (uintptr_t)l->ir;
	a.epass_ir_len = l->ir_len;
	if (l->log) {
		l->log[0] = 0;
		a.log_buf = (uintptr_t)l->log;
		a.log_size = l->log_size;
		a.log_level = 1;
	}
	fd = sys_bpf(BPF_PROG_LOAD, &a);
	return fd < 0 ? -errno : fd;
}

/* The verifier's view of a loaded program (xlated instructions). */
static int xlated(int fd, struct bpf_insn *out, unsigned int max)
{
	struct bpf_prog_info info;
	union bpf_attr a;

	memset(&info, 0, sizeof(info));
	memset(&a, 0, sizeof(a));
	a.info.bpf_fd = fd;
	a.info.info_len = sizeof(info);
	a.info.info = (uintptr_t)&info;
	if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a))
		return -errno;
	if (info.xlated_prog_len / sizeof(*out) > max)
		return -E2BIG;
	unsigned int n = info.xlated_prog_len;
	memset(&info, 0, sizeof(info));
	info.xlated_prog_len = n;
	info.xlated_prog_insns = (uintptr_t)out;
	a.info.info_len = sizeof(info);
	if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a))
		return -errno;
	return n / sizeof(*out);
}

/* Load and return xlated instructions; -errno if the load fails. */
static int load_x(const struct load *l, struct bpf_insn *out)
{
	int fd = load(l), n;

	if (fd < 0)
		return fd;
	n = xlated(fd, out, MAXI);
	close(fd);
	return n;
}

/* ePass in userspace (libepass.a): 0 and the output, or the ABI code. */
static int user_epass(const struct bpf_insn *p, unsigned int cnt, const void *ir, unsigned int ir_len,
		      const char *gopt, const char *popt, struct bpf_insn *out, unsigned int *out_cnt)
{
	struct epass_input in = {
		.insns = (const struct epass_insn *)p,
		.insn_cnt = cnt,
		.ir = ir,
		.ir_len = ir_len,
		.gopt = gopt,
		.gopt_len = gopt ? strlen(gopt) : 0,
		.popt = popt,
		.popt_len = popt ? strlen(popt) : 0,
		.flags = EPASS_IN_REQUESTED,
	};
	struct epass_output o;
	int rc = epass_compile(epass_default_host(), NULL, NULL, &in, &o);

	if (rc == 0) {
		memcpy(out, o.insns, o.insn_cnt * sizeof(*out));
		*out_cnt = o.insn_cnt;
	}
	epass_output_free(&o);
	return rc;
}

static int set_policy(const char *s)
{
	int fd = open(POLICY, O_WRONLY), r = 0;

	if (fd < 0)
		return -errno;
	if (write(fd, s, strlen(s)) < 0)
		r = -errno;
	close(fd);
	return r;
}

static void get_policy(char *buf, size_t n)
{
	int fd = open(POLICY, O_RDONLY);
	ssize_t r = fd < 0 ? -1 : read(fd, buf, n - 1);

	buf[r > 0 ? r : 0] = 0;
	if (fd >= 0)
		close(fd);
}

static int same(const struct bpf_insn *a, int na, const struct bpf_insn *b, int nb)
{
	return na > 0 && na == nb && !memcmp(a, b, na * sizeof(*a));
}

/* kernel(P, flags, gopt, popt) == verifier(userspace ePass(P)) */
static void check_identical(const char *what, const struct bpf_insn *p, unsigned int cnt,
			    const void *ir, unsigned int ir_len, const char *gopt, const char *popt,
			    unsigned int flags)
{
	static struct bpf_insn ux[MAXI], kx[MAXI], u[MAXI];
	unsigned int un = 0;
	int rc = user_epass(p, cnt, ir, ir_len, gopt, popt, u, &un);
	struct load lk = { p, cnt, ir, ir_len, gopt, popt, flags, NULL, 0 };
	struct load lu = { u, un, NULL, 0, NULL, NULL, 0, NULL, 0 };
	int kn = load_x(&lk, kx);
	int xn = rc == 0 ? load_x(&lu, ux) : -1;

	CHECK(rc == 0, "%s: userspace ePass returned %d", what, rc);
	CHECK(kn > 0, "%s: kernel ePass load failed: %d", what, kn);
	CHECK(xn > 0, "%s: loading the userspace output failed: %d", what, xn);
	CHECK(same(kx, kn, ux, xn), "%s: kernel (%d) and userspace (%d) ePass differ", what, kn, xn);
}

static void *read_file(const char *path, unsigned int *len)
{
	FILE *f = fopen(path, "rb");
	static char buf[1 << 20];
	size_t n;

	if (!f)
		return NULL;
	n = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	*len = n;
	return buf;
}

/*
 * epass_selftest stress <dump files...>: run in-kernel ePass on real
 * programs (one u64 per line). The verifier may reject them (their map fds
 * are stale); this checks that ePass itself completes on every one: its log
 * reports a result, and the kernel stays healthy (check dmesg).
 */
static int stress(int argc, char **argv)
{
	static struct bpf_insn p[1 << 17];
	static char log[1 << 20];
	int i, ran = 0, compiled = 0, open_fail = 0, other = 0;

	for (i = 0; i < argc; i++) {
		FILE *f = fopen(argv[i], "r");
		unsigned long long raw;
		unsigned int n = 0;
		char line[64];

		if (!f)
			continue;
		while (n < (1 << 17) && fgets(line, sizeof(line), f) && line[0] != '\n')
			if (sscanf(line, "%llu", &raw) == 1)
				memcpy(&p[n++], &raw, sizeof(raw));
		fclose(f);
		if (!n)
			continue;
		union bpf_attr a;

		memset(&a, 0, sizeof(a));
		a.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
		a.insns = (uintptr_t)p;
		a.insn_cnt = n;
		a.license = (uintptr_t)"GPL";
		a.prog_flags = BPF_F_EPASS;
		a.epass_gopt = (uintptr_t)"verbose=2";
		a.epass_gopt_len = 9;
		a.log_buf = (uintptr_t)log;
		a.log_size = sizeof(log);
		a.log_level = 1;
		log[0] = 0;
		int fd = sys_bpf(BPF_PROG_LOAD, &a);

		if (fd >= 0)
			close(fd);
		ran++;
		if (strstr(log, "instructions (isa"))
			compiled++;
		else if (strstr(log, "loading the original"))
			open_fail++;
		else
			other++;
	}
	printf("stress: %d programs, %d compiled by ePass, %d failed open, %d other\n", ran, compiled,
	       open_fail, other);
	return 0;
}

int main(int argc, char **argv)
{
	static char log[1 << 16];
	static struct bpf_insn x[MAXI], y[MAXI];
	char path[512], saved[4096];
	unsigned int blob_len = 0, n1 = sizeof(p1) / sizeof(p1[0]);
	void *blob;
	int r, n, m;

	if (argc > 1 && !strcmp(argv[1], "stress"))
		return stress(argc - 2, argv + 2);
	snprintf(path, sizeof(path), "%s/p1.blob", argc > 1 ? argv[1] : ".");
	blob = read_file(path, &blob_len);
	get_policy(saved, sizeof(saved));
	printf("policy: \"%s\"\n", saved);
	set_policy("mode=optin");

	/* Untouched unless requested. */
	n = load_x(&(struct load){ p1, n1 }, x);
	m = load_x(&(struct load){ p1, n1, .flags = BPF_F_EPASS }, y);
	CHECK(n > 0 && m > 0, "baseline loads: %d %d", n, m);
	CHECK(!same(x, n, y, m), "ePass changed nothing on p1");

	/* Kernel == userspace. */
	check_identical("p1 flag", p1, n1, NULL, 0, NULL, NULL, BPF_F_EPASS);
	check_identical("p1 gopt", p1, n1, NULL, 0, "verbose=2", NULL, 0);
	check_identical("p1 popt", p1, n1, NULL, 0, NULL, "!const_prop", BPF_F_EPASS);
	check_identical("p1 isa", p1, n1, NULL, 0, "isa=v1,ra_colors=4", NULL, BPF_F_EPASS);
	check_identical("p2 loop", p2, 6, NULL, 0, NULL, NULL, BPF_F_EPASS);
	if (blob)
		check_identical("p1 IR", NULL, 0, blob, blob_len, NULL, NULL, 0);
	else
		CHECK(0, "no %s", path);

	/* The ePass log leads the verifier log. */
	r = load(&(struct load){ p1, n1, .gopt = "verbose=2", .log = log, .log_size = sizeof(log) });
	CHECK(r >= 0 && strstr(log, "epass: "), "no ePass lines in the verifier log: %d\n%s", r, log);
	if (r >= 0)
		close(r);

	/* Option errors reject, with the reason in the log. */
	r = load(&(struct load){ p1, n1, .gopt = "frobnicate", .log = log, .log_size = sizeof(log) });
	CHECK(r == -EINVAL && strstr(log, "gopt"), "bad gopt: %d, log: %s", r, log);
	r = load(&(struct load){ p1, n1, .popt = "nosuchpass" });
	CHECK(r == -EINVAL, "bad popt: %d", r);

	/* IR input errors. */
	if (blob) {
		static char bad[1 << 20];

		r = load(&(struct load){ p1, n1, .ir = blob, .ir_len = blob_len });
		CHECK(r == -EINVAL, "IR with instructions: %d", r);
		memcpy(bad, blob, blob_len);
		bad[40] ^= 0xff;
		r = load(&(struct load){ NULL, 0, .ir = bad, .ir_len = blob_len });
		CHECK(r < 0, "corrupt IR loaded");
	}

	/* Unsupported input fails open: the original loads. */
	r = load(&(struct load){ p3, 4, .flags = BPF_F_EPASS, .gopt = "verbose=1", .log = log,
				 .log_size = sizeof(log) });
	CHECK(r >= 0 && strstr(log, "unsupported"), "bpf-to-bpf fail-open: %d, log: %s", r, log);
	if (r >= 0)
		close(r);

	/* Policy: off. */
	CHECK(set_policy("mode=off") == 0, "set mode=off");
	m = load_x(&(struct load){ p1, n1, .flags = BPF_F_EPASS }, y);
	CHECK(same(x, n, y, m), "mode=off still rewrote the program");
	if (blob) {
		r = load(&(struct load){ NULL, 0, .ir = blob, .ir_len = blob_len });
		CHECK(r == -EPERM, "IR under mode=off: %d", r);
	}

	/* Policy: always (no request needed), forced passes. */
	CHECK(set_policy("mode=always") == 0, "set mode=always");
	check_identical("always", p1, n1, NULL, 0, NULL, NULL, 0);
	CHECK(set_policy("mode=optin,+const_prop") == 0, "set forced");
	check_identical("forced", p1, n1, NULL, 0, NULL, NULL, 0);
	r = load(&(struct load){ p1, n1, .popt = "!const_prop" });
	CHECK(r == -EPERM, "loader disabling a forced pass: %d", r);

	/* Policy: denied passes, no loader popt, no IR. */
	CHECK(set_policy("-const_prop") == 0, "set denied");
	r = load(&(struct load){ p1, n1, .popt = "const_prop" });
	CHECK(r == -EPERM, "loader enabling a denied pass: %d", r);
	CHECK(set_policy("user_popt=0") == 0, "set user_popt=0");
	r = load(&(struct load){ p1, n1, .popt = "dce" });
	CHECK(r == -EPERM, "popt with user_popt=0: %d", r);
	if (blob) {
		CHECK(set_policy("ir=0") == 0, "set ir=0");
		r = load(&(struct load){ NULL, 0, .ir = blob, .ir_len = blob_len });
		CHECK(r == -EPERM, "IR with ir=0: %d", r);
	}

	/* Invalid policies are refused and leave the policy unchanged. */
	CHECK(set_policy("mode=optin") == 0, "reset");
	CHECK(set_policy("mode=sometimes") == -EINVAL, "invalid policy accepted");
	CHECK(set_policy("+nosuchpass") == -EINVAL, "unknown pass accepted");
	get_policy(path, sizeof(path));
	CHECK(!strncmp(path, "mode=optin", 10), "policy changed to \"%s\"", path);

	set_policy(saved[0] ? saved : "mode=optin");
	printf("%d passed, %d failed\n", passes, failures);
	return failures ? 1 : 0;
}
