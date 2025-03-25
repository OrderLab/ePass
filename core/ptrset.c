// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

// An efficient pointer hashset data structure

#define STEP 31

// Make sure size > 0
void bpf_ir_ptrset_init(struct bpf_ir_env *env, struct ptrset *res, size_t size)
{
	SAFE_MALLOC(res->set, size * sizeof(struct ptrset_entry));
	res->size = size;
	res->cnt = 0;
}

static void bpf_ir_ptrset_insert_raw(struct ptrset *set, void *key)
{
	u32 index = hash32_ptr(key) % set->size;
	for (u32 i = 0; i < set->size; ++i) {
		if (set->set[index].occupy <= 0) {
			// Found an empty slot
			set->set[index].key = key;
			set->set[index].occupy = 1;
			set->cnt++;
			return;
		} else if (set->set[index].key == key) {
			// Found
			return;
		}
		index = (index + STEP) % set->size;
	}
	CRITICAL("Impossible");
}

void bpf_ir_ptrset_insert(struct bpf_ir_env *env, struct ptrset *set, void *key)
{
	if (set->cnt >= set->size) {
		// Table is full, grow it
		size_t new_size = set->size * 2;
		struct ptrset new_table;
		bpf_ir_ptrset_init(env, &new_table, new_size);
		for (size_t i = 0; i < set->size; ++i) {
			if (set->set[i].occupy > 0) {
				bpf_ir_ptrset_insert_raw(&new_table,
							 set->set[i].key);
			}
		}
		free_proto(set->set);
		set->set = new_table.set;
		set->size = new_table.size;
	}
	bpf_ir_ptrset_insert_raw(set, key);
}

int bpf_ir_ptrset_delete(struct ptrset *set, void *key)
{
	u32 index = hash32_ptr(key) % set->size;
	for (u32 i = 0; i < set->size; ++i) {
		if (set->set[index].occupy == 0) {
			// Already deleted
			return -1;
		}
		if (set->set[index].occupy == 1) {
			if (set->set[index].key == key) {
				// Found
				set->set[index].occupy = -1;
				set->cnt--;
				return 0;
			}
		}
		index = (index + STEP) % set->size;
	}
	return -1;
}

bool bpf_ir_ptrset_exists(struct ptrset *set, void *key)
{
	u32 index = hash32_ptr(key) % set->size;
	for (u32 i = 0; i < set->size; ++i) {
		if (set->set[index].occupy == 0) {
			// Not found
			return false;
		}
		if (set->set[index].occupy == 1) {
			if (set->set[index].key == key) {
				// Found
				return true;
			}
		}
		index = (index + STEP) % set->size;
	}
	return NULL;
}

void bpf_ir_ptrset_print_dbg(struct bpf_ir_env *env, struct ptrset *set,
			     void (*print_key)(struct bpf_ir_env *env, void *))
{
	for (size_t i = 0; i < set->size; ++i) {
		if (set->set[i].occupy > 0) {
			print_key(env, set->set[i].key);
			PRINT_LOG_DEBUG(env, " ");
		}
	}
	PRINT_LOG_DEBUG(env, "\n");
}

void bpf_ir_ptrset_clean(struct ptrset *set)
{
	for (size_t i = 0; i < set->size; ++i) {
		set->set[i].key = NULL;
		set->set[i].occupy = 0;
	}
	set->cnt = 0;
}

void bpf_ir_ptrset_free(struct ptrset *set)
{
	bpf_ir_ptrset_clean(set);
	if (set->set) {
		free_proto(set->set);
	}
	set->size = 0;
	set->set = NULL;
}

void **bpf_ir_ptrset_next(struct ptrset *set, void **keyd)
{
	struct ptrset_entry *cc;
	if (keyd == NULL) {
		cc = set->set;
	} else {
		cc = container_of(keyd, struct ptrset_entry, key) + 1;
	}
	while ((size_t)(cc - set->set) < set->size) {
		if (cc->occupy == 1) {
			return &cc->key;
		}
		cc++;
	}
	return NULL;
}

struct ptrset bpf_ir_ptrset_union(struct bpf_ir_env *env, struct ptrset *set1,
				  struct ptrset *set2)
{
	struct ptrset res;
	bpf_ir_ptrset_init(env, &res, set1->cnt + set2->cnt);
	for (size_t i = 0; i < set1->size; ++i) {
		if (set1->set[i].occupy > 0) {
			bpf_ir_ptrset_insert(env, &res, set1->set[i].key);
		}
	}
	for (size_t i = 0; i < set2->size; ++i) {
		if (set2->set[i].occupy > 0) {
			bpf_ir_ptrset_insert(env, &res, set2->set[i].key);
		}
	}
	return res;
}

struct ptrset bpf_ir_ptrset_intersec(struct bpf_ir_env *env,
				     struct ptrset *set1, struct ptrset *set2)
{
	struct ptrset res;
	bpf_ir_ptrset_init(env, &res, set1->cnt);
	for (size_t i = 0; i < set1->size; ++i) {
		if (set1->set[i].occupy > 0 &&
		    bpf_ir_ptrset_exists(set2, set1->set[i].key)) {
			bpf_ir_ptrset_insert(env, &res, set1->set[i].key);
		}
	}
	return res;
}

// Move set2 to set1
void bpf_ir_ptrset_move(struct ptrset *set1, struct ptrset *set2)
{
	bpf_ir_ptrset_free(set1);
	*set1 = *set2;
	set2->set = NULL;
	set2->cnt = 0;
	set2->size = 0;
}

// Clone set2 to set1
// Make sure set1 is empty (no data)
void bpf_ir_ptrset_clone(struct bpf_ir_env *env, struct ptrset *set1,
			 struct ptrset *set2)
{
	bpf_ir_ptrset_init(env, set1, set2->size);
	for (size_t i = 0; i < set2->size; ++i) {
		if (set2->set[i].occupy > 0) {
			bpf_ir_ptrset_insert(env, set1, set2->set[i].key);
		}
	}
}

// set1 += set2
void bpf_ir_ptrset_add(struct bpf_ir_env *env, struct ptrset *set1,
		       struct ptrset *set2)
{
	for (size_t i = 0; i < set2->size; ++i) {
		if (set2->set[i].occupy > 0) {
			bpf_ir_ptrset_insert(env, set1, set2->set[i].key);
		}
	}
}

// set1 -= set2
void bpf_ir_ptrset_minus(struct ptrset *set1, struct ptrset *set2)
{
	for (size_t i = 0; i < set2->size; ++i) {
		if (set2->set[i].occupy > 0) {
			bpf_ir_ptrset_delete(set1, set2->set[i].key);
		}
	}
}
