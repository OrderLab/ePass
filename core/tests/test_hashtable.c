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

static u32 hash(const char *s)
{
	u32 key = 0;
	char c;

	while ((c = *s++))
		key += c;

	return key;
}

void print_key(struct bpf_ir_env *env, void *key)
{
	char *s = (char *)key;
	PRINT_LOG_DEBUG(env, "%s", s);
}

void print_data(struct bpf_ir_env *env, void *data)
{
	int *i = (int *)data;
	PRINT_LOG_DEBUG(env, "%d", *i);
}

void test(void)
{
	struct bpf_ir_opts opts = bpf_ir_default_opts();
	opts.verbose = 5;
	struct bpf_ir_env *env = bpf_ir_init_env(opts, NULL, 0);

	struct hashtbl tbl;
	bpf_ir_hashtbl_init(env, &tbl, 8);

	for (int i = 0; i < 5; i++) {
		char name[32];
		sprintf(name, "node%d", i);
		hashtbl_insert(env, &tbl, name, hash(name), i);
	}

	bpf_ir_hashtbl_print_dbg(env, &tbl, print_key, print_data);

	PRINT_LOG_DEBUG(env, "Delete\n");

	for (int i = 0; i < 3; i++) {
		char name[32];
		sprintf(name, "node%d", i);
		hashtbl_delete(env, &tbl, name, hash(name));
	}

	bpf_ir_hashtbl_print_dbg(env, &tbl, print_key, print_data);

	PRINT_LOG_DEBUG(env, "Rehash\n");

	for (int i = 0; i < 8; i++) {
		char name[32];
		sprintf(name, "node%d", i);
		int tmp = 8 - i;
		hashtbl_insert(env, &tbl, name, hash(name), tmp);
	}

	bpf_ir_hashtbl_print_dbg(env, &tbl, print_key, print_data);

	PRINT_LOG_DEBUG(env, "Get\n");

	for (int i = 0; i < 10; i++) {
		char name[32];
		sprintf(name, "node%d", i);
		int *tmp = hashtbl_get(env, &tbl, name, hash(name), int);
		if (tmp) {
			PRINT_LOG_DEBUG(env, "GET %s %d\n", name, *tmp);
		} else {
			PRINT_LOG_DEBUG(env, "GET %s NULL\n", name);
		}
	}

	PRINT_LOG_DEBUG(env, "Clean\n");

	bpf_ir_hashtbl_clean(&tbl);

	bpf_ir_hashtbl_print_dbg(env, &tbl, print_key, print_data);

	PRINT_LOG_DEBUG(env, "Extend\n");

	for (int i = 0; i < 100; i++) {
		char name[32];
		sprintf(name, "node%d", i);
		hashtbl_insert(env, &tbl, name, hash(name), i);
	}

	bpf_ir_hashtbl_print_dbg(env, &tbl, print_key, print_data);

	bpf_ir_hashtbl_free(&tbl);

	bpf_ir_free_env(env);
}

int main(void)
{
	test();
	return 0;
}
