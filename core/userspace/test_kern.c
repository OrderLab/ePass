// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <linux/bpf_ir.h>

int main(void)
{
	struct bpf_ir_opts opts = bpf_ir_default_opts();
	struct bpf_ir_env *env = bpf_ir_init_env(opts, NULL, 0);
	int ret = bpf_ir_init_opts(env, "ads(a=1),qvq(ds),sd),fd,ff(fd?)",
				   "print_bpf,verbose=02,maxit=10");
	assert(ret == 0);
	ret = bpf_ir_init_opts(env, "a", "");
	assert(ret == 0);
	return ret;
}
