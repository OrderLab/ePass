// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

void bpf_ir_array_init(struct array *res, size_t size)
{
	res->data = NULL;
	res->max_elem = 0;
	res->elem_size = size;
	res->num_elem = 0;
}

struct array bpf_ir_array_null(void)
{
	struct array res;
	res.data = NULL;
	res.max_elem = 0;
	res.elem_size = 0;
	res.num_elem = 0;
	return res;
}

void bpf_ir_array_push(struct bpf_ir_env *env, struct array *arr, void *data)
{
	if (arr->data == NULL) {
		SAFE_MALLOC(arr->data, arr->elem_size * 2)
		arr->max_elem = 2;
	}
	if (arr->num_elem >= arr->max_elem) {
		// Reallocate
		void *new_data = NULL;
		SAFE_MALLOC(new_data, arr->max_elem * 2 * arr->elem_size);
		memcpy(new_data, arr->data, arr->num_elem * arr->elem_size);
		free_proto(arr->data);
		arr->data = new_data;
		arr->max_elem *= 2;
	}
	// Push back
	memcpy((char *)(arr->data) + arr->elem_size * arr->num_elem, data,
	       arr->elem_size);
	arr->num_elem++;
}

void bpf_ir_array_push_unique(struct bpf_ir_env *env, struct array *arr,
			      void *data)
{
	for (size_t i = 0; i < arr->num_elem; ++i) {
		if (memcmp((char *)(arr->data) + arr->elem_size * i, data,
			   arr->elem_size) == 0) {
			return;
		}
	}
	bpf_ir_array_push(env, arr, data);
}

void bpf_ir_array_erase(struct array *arr, size_t idx)
{
	if (idx >= arr->num_elem) {
		return;
	}
	// Shift elements
	for (size_t i = idx; i < arr->num_elem - 1; ++i) {
		memcpy((char *)(arr->data) + arr->elem_size * i,
		       (char *)(arr->data) + arr->elem_size * (i + 1),
		       arr->elem_size);
	}
	arr->num_elem--;
}

void bpf_ir_array_clear(struct bpf_ir_env *env, struct array *arr)
{
	free_proto(arr->data);
	SAFE_MALLOC(arr->data, arr->elem_size * 4);
	arr->max_elem = 4;
	arr->num_elem = 0;
}

// No need to initialize the res array
void bpf_ir_array_clone(struct bpf_ir_env *env, struct array *res,
			struct array *arr)
{
	res->num_elem = arr->num_elem;
	res->max_elem = arr->max_elem;
	res->elem_size = arr->elem_size;
	if (arr->num_elem == 0) {
		res->data = NULL;
		return;
	}
	SAFE_MALLOC(res->data, arr->max_elem * arr->elem_size);
	memcpy(res->data, arr->data, arr->num_elem * arr->elem_size);
}

// Merge b into a
void bpf_ir_array_merge(struct bpf_ir_env *env, struct array *a,
			struct array *b)
{
	struct ir_insn **pos;
	array_for(pos, (*b))
	{
		struct ir_insn *insn = *pos;
		bpf_ir_array_push_unique(env, a, &insn);
		CHECK_ERR();
	}
}
void bpf_ir_array_free(struct array *arr)
{
	if (arr->data) {
		free_proto(arr->data);
	}
	*arr = bpf_ir_array_null();
}

void *bpf_ir_array_get_void(struct array *arr, size_t idx)
{
	if (idx >= arr->num_elem) {
		return NULL;
	}
	return (char *)(arr->data) + arr->elem_size * idx;
}
