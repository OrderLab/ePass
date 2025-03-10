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

void test(int initsize)
{
	struct bpf_ir_opts opts = bpf_ir_default_opts();
	opts.verbose = 5;
	struct bpf_ir_env *env = bpf_ir_init_env(opts, NULL, 0);

	struct ptrset set;
	bpf_ir_ptrset_init(env, &set, initsize);

	char strmap[10][10] = { "hello", "world", "foo",   "bar",    "baz",
				"qux",	 "quux",  "corge", "grault", "garply" };

	for (int i = 0; i < 10; i++) {
		bpf_ir_ptrset_insert(env, &set, strmap[i]);
	}

	DBGASSERT(set.cnt == 10);

	bpf_ir_ptrset_print_dbg(env, &set, print_key);

	for (int j = 0; j < 20; ++j) {
		for (int i = 0; i < 10; i++) {
			bpf_ir_ptrset_insert(env, &set, strmap[i]);
		}
	}

	DBGASSERT(set.cnt == 10);

	// Should output the same as the previous one
	bpf_ir_ptrset_print_dbg(env, &set, print_key);

	for (int i = 0; i < 10; i++) {
		int ret = bpf_ir_ptrset_delete(&set, strmap[i]);
		if (ret != 0) {
			PRINT_LOG_DEBUG(env, "Failed to delete %s\n",
					strmap[i]);
		}
	}

	// for (int i = 0; i < 10; i++) {
	// 	u32 index = hash32_ptr(strmap[i]) % set.size;
	// 	PRINT_LOG_DEBUG(env, "hash32_ptr(%s) = %u\n", strmap[i], index);
	// }

	bpf_ir_ptrset_print_dbg(env, &set, print_key);
	DBGASSERT(set.cnt == 0);

	bpf_ir_free_env(env);
}

int main(void)
{
	for (int i = 1; i < 10; i++) {
		test(i);
	}
	return 0;
}
