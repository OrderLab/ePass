// SPDX-License-Identifier: GPL-2.0-only
/*
 * ePass: run the ePass v2 compiler on eBPF programs at BPF_PROG_LOAD.
 *
 * The compiler is the Rust object in kernel/bpf/epass/ (the no_std
 * epass-core crate, synced from the ePass repository). This file is its
 * kernel side:
 *
 *  - the host: memory (kvmalloc), time, rescheduling and fatal signals;
 *  - the facts: helper prototypes from the program type's verifier ops,
 *    kfunc prototypes from vmlinux BTF;
 *  - the administrator policy (sysctl kernel.bpf_epass_policy);
 *  - the glue around bpf_prog_load(): option and IR input, replacing the
 *    program, remapping line_info, and the ePass log in the verifier log.
 *
 * The verifier still checks whatever ePass produces: an ePass bug can make
 * a load fail, never let an unsafe program in.
 */

#include <linux/bpf.h>
#include <linux/bpf_epass.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/sysctl.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>

#include "epass/epass.h"

#define EPASS_POLICY_MAX 4096
#define EPASS_OPT_MAX 4096
#define EPASS_IR_MAX (16U << 20)
#define EPASS_LINFO_MAX_BYTES (64U << 20)

struct bpf_epass_info {
	struct epass_output out;
	void *line_info;	/* remapped copy, line_info_rec_size records */
	u32 line_info_cnt;
};

/* ------------------------------------------------------------------ host */

static void *epass_alloc(void *ctx, size_t size, size_t align)
{
	/* kvmalloc() memory is at least 8-byte aligned; ePass never needs more. */
	if (align > 8)
		return NULL;
	return kvmalloc(size, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
}

static void epass_free(void *ctx, void *ptr, size_t size, size_t align)
{
	kvfree(ptr);
}

static u64 epass_now_ns(void *ctx)
{
	return ktime_get_ns();
}

static int epass_should_yield(void *ctx)
{
	cond_resched();
	return fatal_signal_pending(current);
}

static const struct epass_host epass_host = {
	.alloc = epass_alloc,
	.free = epass_free,
	.now_ns = epass_now_ns,
	.should_yield = epass_should_yield,
};

/* ----------------------------------------------------------------- facts */

static int epass_helper(void *ctx, s32 id, struct epass_sig *sig)
{
	const struct bpf_prog *prog = ctx;
	const struct bpf_func_proto *fn;
	int i, n = 0;

	if (id <= 0 || id >= __BPF_FUNC_MAX_ID)
		return -ENOENT;
	fn = bpf_epass_func_proto(id, prog);
	if (!fn)
		return -ENOENT;
	/* Arguments the verifier does not check (ARG_DONTCARE) are not read. */
	for (i = 0; i < 5; i++)
		if (fn->arg_type[i] != ARG_DONTCARE)
			n = i + 1;
	sig->nargs = n;
	sig->optional_from = n;
	switch (base_type(fn->ret_type)) {
	case RET_INTEGER:
	case RET_VOID:
		sig->ret = EPASS_RET_SCALAR;
		break;
	case RET_PTR_TO_MAP_VALUE:
		sig->ret = type_may_be_null(fn->ret_type) ? EPASS_RET_MAP_VALUE_OR_NULL :
							    EPASS_RET_PTR;
		break;
	case RET_PTR_TO_MEM:
		sig->ret = type_may_be_null(fn->ret_type) ? EPASS_RET_MEM_OR_NULL : EPASS_RET_PTR;
		break;
	default:
		sig->ret = EPASS_RET_PTR;
		break;
	}
	return 0;
}

static int epass_kfunc(void *ctx, s32 btf_id, s16 fd_idx, struct epass_sig *sig)
{
	const struct btf_type *t, *proto, *ret;
	struct btf *btf;

	/* Module kfuncs (through fd_array) are not resolved yet. */
	if (fd_idx || btf_id <= 0)
		return -ENOENT;
	btf = bpf_get_btf_vmlinux();
	if (IS_ERR_OR_NULL(btf))
		return -ENOENT;
	t = btf_type_by_id(btf, btf_id);
	if (!t || !btf_type_is_func(t))
		return -ENOENT;
	proto = btf_type_by_id(btf, t->type);
	if (!proto || !btf_type_is_func_proto(proto) || btf_type_vlen(proto) > 5)
		return -ENOENT;
	sig->nargs = btf_type_vlen(proto);
	sig->optional_from = sig->nargs;
	ret = btf_type_skip_modifiers(btf, proto->type, NULL);
	sig->ret = ret && btf_type_is_ptr(ret) ? EPASS_RET_PTR : EPASS_RET_SCALAR;
	return 0;
}

/* ---------------------------------------------------------------- policy */

static DEFINE_MUTEX(epass_policy_lock);
static char epass_policy[EPASS_POLICY_MAX] = "mode=optin";
/* epass_policy_check() of epass_policy, read locklessly on every load. */
static int epass_policy_summary = EPASS_MODE_OPTIN | EPASS_POLICY_IR | EPASS_POLICY_USER_POPT;

static int epass_policy_sysctl(const struct ctl_table *table, int write, void *buffer,
			       size_t *lenp, loff_t *ppos)
{
	struct ctl_table tmp = *table;
	char *val;
	int ret, sum;

	if (!write) {
		mutex_lock(&epass_policy_lock);
		ret = proc_dostring(table, write, buffer, lenp, ppos);
		mutex_unlock(&epass_policy_lock);
		return ret;
	}
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	val = kzalloc(EPASS_POLICY_MAX, GFP_KERNEL);
	if (!val)
		return -ENOMEM;
	tmp.data = val;
	ret = proc_dostring(&tmp, write, buffer, lenp, ppos);
	if (ret)
		goto out;
	sum = epass_policy_check(&epass_host, val, strnlen(val, EPASS_POLICY_MAX));
	if (sum < 0) {
		ret = sum;
		goto out;
	}
	mutex_lock(&epass_policy_lock);
	strscpy(epass_policy, val, sizeof(epass_policy));
	WRITE_ONCE(epass_policy_summary, sum);
	mutex_unlock(&epass_policy_lock);
	pr_info("epass: policy set to \"%s\"\n", val);
out:
	kfree(val);
	return ret;
}

static const struct ctl_table epass_sysctls[] = {
	{
		.procname = "bpf_epass_policy",
		.data = epass_policy,
		.maxlen = EPASS_POLICY_MAX,
		.mode = 0644,
		.proc_handler = epass_policy_sysctl,
	},
};

static int __init epass_init(void)
{
	register_sysctl_init("kernel", epass_sysctls);
	return 0;
}
late_initcall(epass_init);

/* ---------------------------------------------------------------- inputs */

/* Copy a user (or kernel) buffer of len bytes; NULL with *err on failure. */
static void *epass_copy_in(u64 addr, u32 len, bpfptr_t uattr, int *err)
{
	void *buf;

	if (!len)
		return NULL;
	buf = kvmalloc(len, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!buf) {
		*err = -ENOMEM;
		return NULL;
	}
	if (copy_from_bpfptr(buf, make_bpfptr(addr, uattr.is_kernel), len)) {
		kvfree(buf);
		*err = -EFAULT;
		return NULL;
	}
	return buf;
}

/* Give the loader the ePass log when the load is rejected before the
 * verifier (which otherwise carries it, see bpf_epass_log()).
 */
static void epass_log_to_user(struct bpf_log_attr *attr_log, const struct epass_output *out)
{
	u32 n;

	if (!attr_log || !attr_log->level || !attr_log->ubuf || !attr_log->size || !out->log)
		return;
	n = min(out->log_len, attr_log->size - 1);
	if (copy_to_user(attr_log->ubuf, out->log, n))
		return;
	put_user(0, attr_log->ubuf + n);
}

struct epass_linfo_key {
	u32 off;
	u32 idx;
};

static int epass_linfo_cmp(const void *a, const void *b)
{
	const struct epass_linfo_key *x = a, *y = b;

	if (x->off != y->off)
		return x->off < y->off ? -1 : 1;
	return x->idx < y->idx ? -1 : x->idx > y->idx;
}

/*
 * Remap line_info to the rewritten program. Records keep their size; each
 * insn_off goes through ePass's offset map. Block layout may reorder code,
 * so records are sorted by the new offset, keeping the first one per
 * offset (the verifier wants strictly increasing offsets). -EINVAL means
 * the records are malformed: keep the original program so the verifier
 * reports them.
 */
static int epass_remap_line_info(struct bpf_epass_info *info, const union bpf_attr *attr,
				 bpfptr_t uattr, u32 orig_len)
{
	u32 cnt = attr->line_info_cnt, rs = attr->line_info_rec_size, i, n = 0, m = 0;
	const struct epass_output *out = &info->out;
	struct epass_linfo_key *keys = NULL;
	char *recs, *res = NULL;
	int err = 0;

	if (rs < sizeof(struct bpf_line_info) || rs > 252 || rs % sizeof(u32) ||
	    cnt > EPASS_LINFO_MAX_BYTES / rs || out->offsets_cnt != orig_len + 1)
		return -EINVAL;
	recs = epass_copy_in(attr->line_info, cnt * rs, uattr, &err);
	if (!recs)
		return err;
	keys = kvmalloc_array(cnt, sizeof(*keys), GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	res = kvmalloc_array(cnt, rs, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!keys || !res) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < cnt; i++) {
		u32 off = ((struct bpf_line_info *)(recs + (size_t)i * rs))->insn_off;

		if (off >= orig_len) {
			err = -EINVAL;
			goto out;
		}
		if (out->offsets[off] >= out->insn_cnt)
			continue;
		keys[n].off = out->offsets[off];
		keys[n].idx = i;
		n++;
	}
	sort(keys, n, sizeof(*keys), epass_linfo_cmp, NULL);
	for (i = 0; i < n; i++) {
		char *dst = res + (size_t)m * rs;

		if (i && keys[i].off == keys[i - 1].off)
			continue;
		memcpy(dst, recs + (size_t)keys[i].idx * rs, rs);
		((struct bpf_line_info *)dst)->insn_off = keys[i].off;
		m++;
	}
	info->line_info = res;
	info->line_info_cnt = m;
	res = NULL;
out:
	kvfree(res);
	kvfree(keys);
	kvfree(recs);
	return err;
}

/* ------------------------------------------------------------------ load */

int bpf_epass_prog_load(struct bpf_prog **progp, union bpf_attr *attr, bpfptr_t uattr,
			struct bpf_log_attr *attr_log, bool bpf_cap)
{
	struct bpf_prog *prog = *progp, *new;
	bool ir = attr->epass_ir_len, requested = bpf_epass_attr_used(attr);
	int sum = READ_ONCE(epass_policy_summary);
	int mode = sum & EPASS_POLICY_MODE_MASK;
	bool forced = sum & EPASS_POLICY_FORCED;
	char *gopt = NULL, *popt = NULL, *policy = NULL;
	void *blob = NULL;
	struct bpf_epass_info *info;
	struct epass_facts facts;
	struct epass_policy pol;
	struct epass_input in;
	int err = 0, rc;
	u32 n;

	if (ir && attr->insn_cnt)
		return -EINVAL;
	if (!ir && (mode == EPASS_MODE_OFF ||
		    (mode == EPASS_MODE_OPTIN && !requested && !forced)))
		return 0;
	/* Pass options and IR are privileged; global options are not. */
	if (!bpf_cap && (attr->epass_popt_len || ir))
		return -EPERM;
	if (attr->epass_gopt_len > EPASS_OPT_MAX || attr->epass_popt_len > EPASS_OPT_MAX ||
	    attr->epass_ir_len > EPASS_IR_MAX)
		return -E2BIG;
	/*
	 * CO-RE relocations name instructions ePass may rewrite, and
	 * bpf-to-bpf calls (several func_info records) are not supported yet:
	 * keep the original, unless the policy requires ePass.
	 */
	if (attr->core_relo_cnt || attr->func_info_cnt > 1) {
		if (ir)
			return -EINVAL;
		return forced ? -EOPNOTSUPP : 0;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL_ACCOUNT);
	if (!info)
		return -ENOMEM;
	gopt = epass_copy_in(attr->epass_gopt, attr->epass_gopt_len, uattr, &err);
	if (!err)
		popt = epass_copy_in(attr->epass_popt, attr->epass_popt_len, uattr, &err);
	if (!err)
		blob = epass_copy_in(attr->epass_ir, attr->epass_ir_len, uattr, &err);
	if (!err) {
		mutex_lock(&epass_policy_lock);
		policy = kstrdup(epass_policy, GFP_KERNEL);
		mutex_unlock(&epass_policy_lock);
		if (!policy)
			err = -ENOMEM;
	}
	if (err)
		goto out_free;

	facts = (struct epass_facts){
		.ctx = prog,
		.prog_type = prog->type,
		.isa = 4,
		.helper = epass_helper,
		.kfunc = epass_kfunc,
	};
	pol = (struct epass_policy){
		.str = policy,
		.len = strlen(policy),
		.preset = EPASS_PRESET_KERNEL,
	};
	in = (struct epass_input){
		.insns = (const struct epass_insn *)prog->insnsi,
		.insn_cnt = ir ? 0 : prog->len,
		.ir = blob,
		.ir_len = attr->epass_ir_len,
		.gopt = gopt,
		.gopt_len = attr->epass_gopt_len,
		.popt = popt,
		.popt_len = attr->epass_popt_len,
		.flags = requested ? EPASS_IN_REQUESTED : 0,
	};
	rc = epass_compile(&epass_host, &facts, &pol, &in, &info->out);
	if (rc < 0) {
		epass_log_to_user(attr_log, &info->out);
		err = rc;
		goto out_free;
	}
	if (rc == 1) {
		/* IR has no original to fall back to (the core never asks). */
		if (ir) {
			epass_log_to_user(attr_log, &info->out);
			err = info->out.error ?: -EINVAL;
			goto out_free;
		}
		goto keep;	/* original program; the log explains why */
	}

	n = info->out.insn_cnt;
	if (!n || n > (bpf_cap ? BPF_COMPLEXITY_LIMIT_INSNS : BPF_MAXINSNS)) {
		if (ir || forced) {
			err = -E2BIG;
			goto out_free;
		}
		goto keep;
	}
	if (!ir && attr->line_info_cnt) {
		err = epass_remap_line_info(info, attr, uattr, prog->len);
		if (err == -EINVAL && !forced) {
			err = 0;
			goto keep;
		}
		if (err)
			goto out_free;
	}
	new = bpf_prog_realloc(prog, bpf_prog_size(n), GFP_USER);
	if (!new) {
		err = -ENOMEM;
		goto out_free;
	}
	prog = new;
	*progp = prog;
	memcpy(prog->insnsi, info->out.insns, (size_t)n * sizeof(struct bpf_insn));
	prog->len = n;
keep:
	prog->aux->epass = info;
	info = NULL;
out_free:
	if (info) {
		epass_output_free(&info->out);
		kvfree(info->line_info);
		kfree(info);
	}
	kfree(policy);
	kvfree(blob);
	kvfree(popt);
	kvfree(gopt);
	return err;
}

void bpf_epass_prog_done(struct bpf_prog *prog)
{
	struct bpf_epass_info *info = prog->aux->epass;

	if (!info)
		return;
	epass_output_free(&info->out);
	kvfree(info->line_info);
	kfree(info);
	prog->aux->epass = NULL;
}

void bpf_epass_log(struct bpf_verifier_env *env)
{
	const struct bpf_epass_info *info = env->prog->aux->epass;
	const char *p, *end, *nl;

	if (!info || !info->out.log || !bpf_verifier_log_needed(&env->log))
		return;
	/* bpf_log() formats into a 1 KB buffer: one line per call. */
	p = info->out.log;
	end = p + info->out.log_len;
	while (p < end) {
		nl = memchr(p, '\n', end - p);
		if (!nl)
			nl = end;
		bpf_log(&env->log, "%.*s\n", (int)min_t(ptrdiff_t, nl - p, 1000), p);
		p = nl + 1;
	}
}

void bpf_epass_line_info(const struct bpf_prog *prog, bpfptr_t *ulinfo, u32 *nr_linfo)
{
	const struct bpf_epass_info *info = prog->aux->epass;

	if (!info || !info->line_info)
		return;
	*ulinfo = KERNEL_BPFPTR(info->line_info);
	*nr_linfo = info->line_info_cnt;
}
