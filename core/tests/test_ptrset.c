// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

static const struct function_pass pre_passes_def[] = {};

static struct function_pass post_passes_def[] = {};

const struct function_pass *pre_passes = pre_passes_def;
const struct function_pass *post_passes = post_passes_def;

const size_t post_passes_cnt =
	sizeof(post_passes_def) / sizeof(post_passes_def[0]);
const size_t pre_passes_cnt =
	sizeof(pre_passes_def) / sizeof(pre_passes_def[0]);

void print_key(struct bpf_ir_env *env, void *key)
{
	char *s = (char *)key;
	PRINT_LOG_DEBUG(env, "%s", s);
}

void test(void)
{
	struct bpf_ir_opts opts = bpf_ir_default_opts();
	opts.verbose = 5;
	struct bpf_ir_env *env = bpf_ir_init_env(opts, NULL, 0);

	struct ptrset set;
	bpf_ir_ptrset_init(env, &set, 10);

	char strmap[10][10] = { "hello", "world", "foo",   "bar",    "baz",
				"qux",	 "quux",  "corge", "grault", "garply" };

	for (int i = 0; i < 10; i++) {
		bpf_ir_ptrset_insert(env, &set, strmap[i]);
	}

	bpf_ir_ptrset_print_dbg(env, &set, print_key);

	bpf_ir_free_env(env);
}

int main(void)
{
	test();
	return 0;
}
