// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

// An open-addressing hashtable

static u32 hash(u32 x)
{
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = (x >> 16) ^ x;
	return x;
}

// Make sure size > 0
void bpf_ir_hashtbl_init(struct bpf_ir_env *env, struct hashtbl *res,
			 size_t size)
{
	SAFE_MALLOC(res->table, size * sizeof(struct hashtbl_entry));
	res->size = size;
	res->cnt = 0;
}

static void bpf_ir_hashtbl_insert_raw(struct hashtbl *tbl, void *key,
				      u32 key_hash, void *data)
{
	u32 index = hash(key_hash) % tbl->size;
	u32 step = __hash_32(key_hash);
	for (u32 i = 0; i < tbl->size; ++i) {
		if (tbl->table[index].occupy <= 0) {
			// Found an empty slot
			tbl->table[index].key = key;
			tbl->table[index].data = data;
			tbl->table[index].key_hash = key_hash;
			tbl->table[index].occupy = 1;
			tbl->cnt++;
			return;
		}
		index = (index + step) % tbl->size;
	}
	CRITICAL("Impossible");
}

static void bpf_ir_hashtbl_insert_raw_cpy(struct hashtbl *tbl, void *key,
					  size_t key_size, u32 key_hash,
					  void *data, size_t data_size)
{
	u32 index = hash(key_hash) % tbl->size;
	u32 step = __hash_32(key_hash);
	for (u32 i = 0; i < tbl->size; ++i) {
		if (tbl->table[index].occupy <= 0) {
			// Found an empty slot
			memcpy(tbl->table[index].key, key, key_size);
			memcpy(tbl->table[index].data, data, data_size);
			tbl->table[index].key_hash = key_hash;
			tbl->table[index].occupy = 1;
			tbl->cnt++;
			return;
		}
		index = (index + step) % tbl->size;
	}
	CRITICAL("Impossible");
}

void bpf_ir_hashtbl_insert(struct bpf_ir_env *env, struct hashtbl *tbl,
			   void *key, size_t key_size, u32 key_hash, void *data,
			   size_t data_size)
{
	if (tbl->cnt >= tbl->size) {
		// Table is full, grow it
		size_t new_size = tbl->size * 2;
		struct hashtbl new_table;
		bpf_ir_hashtbl_init(env, &new_table, new_size);
		for (size_t i = 0; i < tbl->size; ++i) {
			if (tbl->table[i].occupy > 0) {
				bpf_ir_hashtbl_insert_raw(
					&new_table, tbl->table[i].key,
					tbl->table[i].key_hash,
					tbl->table[i].data);
			}
		}
		// This free does not free the data & key
		free_proto(tbl->table);
		tbl->table = new_table.table;
		tbl->size = new_table.size;
	}
	bpf_ir_hashtbl_insert_raw_cpy(tbl, key, key_size, key_hash, data,
				      data_size);
}

int bpf_ir_hashtbl_delete(struct hashtbl *tbl, void *key, size_t key_size,
			  u32 key_hash)
{
	u32 index = hash(key_hash) % tbl->size;
	u32 step = __hash_32(key_hash);
	for (u32 i = 0; i < tbl->size; ++i) {
		if (tbl->table[index].occupy <= 0) {
			// Not found
			return -1;
		}
		if (tbl->table[index].occupy == 1) {
			if (memcmp(tbl->table[index].key, key, key_size) == 0) {
				// Found
				tbl->table[index].occupy = -1;
				tbl->cnt--;
				return 0;
			}
		}
		index = (index + step) % tbl->size;
	}
	return -1;
}

void *bpf_ir_hashtbl_get(struct hashtbl *tbl, void *key, size_t key_size,
			 u32 key_hash)
{
	u32 index = hash(key_hash) % tbl->size;
	u32 step = __hash_32(key_hash);
	for (u32 i = 0; i < tbl->size; ++i) {
		if (tbl->table[index].occupy <= 0) {
			// Not found
			return NULL;
		}
		if (tbl->table[index].occupy == 1) {
			if (memcmp(tbl->table[index].key, key, key_size) == 0) {
				// Found
				return tbl->table[index].data;
			}
		}
		index = (index + step) % tbl->size;
	}
	return NULL;
}

void bpf_ir_hashtbl_print_dbg(struct bpf_ir_env *env, struct hashtbl *tbl,
			      void (*print_key)(struct bpf_ir_env *env, void *),
			      void (*print_data)(struct bpf_ir_env *env,
						 void *))
{
	for (size_t i = 0; i < tbl->size; ++i) {
		if (tbl->table[i].occupy > 0) {
			PRINT_LOG_DEBUG(env, "Key: ");
			print_key(env, tbl->table[i].key);
			PRINT_LOG_DEBUG(env, "Data: ");
			print_data(env, tbl->table[i].data);
			PRINT_LOG_DEBUG(env, "\n");
		}
	}
}
