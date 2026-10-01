/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ePass: in-kernel eBPF compiler passes at BPF_PROG_LOAD (kernel/bpf/epass.c).
 */
#ifndef _LINUX_BPF_EPASS_H
#define _LINUX_BPF_EPASS_H

#include <linux/bpf.h>
#include <linux/bpfptr.h>

struct bpf_verifier_env;
struct bpf_log_attr;

static inline bool bpf_epass_attr_used(const union bpf_attr *attr)
{
	return (attr->prog_flags & BPF_F_EPASS) || attr->epass_gopt_len ||
	       attr->epass_popt_len || attr->epass_ir_len;
}

#ifdef CONFIG_BPF_EPASS

/* Is the program submitted as ePass IR (insn_cnt must then be 0)? */
static inline bool bpf_epass_ir_input(const union bpf_attr *attr)
{
	return attr->epass_ir_len != 0;
}

/*
 * Run ePass on *prog under the administrator policy (sysctl
 * kernel.bpf_epass_policy). On success *prog may be reallocated and hold
 * the rewritten program; on a fail-open error it keeps the original.
 * Returns 0 or a negative errno to reject the load.
 */
int bpf_epass_prog_load(struct bpf_prog **prog, union bpf_attr *attr, bpfptr_t uattr,
			struct bpf_log_attr *attr_log, bool bpf_cap);

/* Release what bpf_epass_prog_load() attached to the program. */
void bpf_epass_prog_done(struct bpf_prog *prog);

/* Copy the ePass compilation log into the verifier log. */
void bpf_epass_log(struct bpf_verifier_env *env);

/* Substitute line_info remapped to the rewritten program. */
void bpf_epass_line_info(const struct bpf_prog *prog, bpfptr_t *ulinfo, u32 *nr_linfo);

/* The verifier's prototype for helper id in this program (verifier.c). */
const struct bpf_func_proto *bpf_epass_func_proto(enum bpf_func_id id,
						  const struct bpf_prog *prog);

#else /* !CONFIG_BPF_EPASS */

static inline bool bpf_epass_ir_input(const union bpf_attr *attr)
{
	return false;
}

static inline int bpf_epass_prog_load(struct bpf_prog **prog, union bpf_attr *attr,
				      bpfptr_t uattr, struct bpf_log_attr *attr_log,
				      bool bpf_cap)
{
	return bpf_epass_attr_used(attr) ? -EOPNOTSUPP : 0;
}

static inline void bpf_epass_prog_done(struct bpf_prog *prog) {}
static inline void bpf_epass_log(struct bpf_verifier_env *env) {}
static inline void bpf_epass_line_info(const struct bpf_prog *prog, bpfptr_t *ulinfo,
				       u32 *nr_linfo) {}

#endif /* CONFIG_BPF_EPASS */

#endif /* _LINUX_BPF_EPASS_H */
