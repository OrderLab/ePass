#ifndef __ARRAY_H__
#define __ARRAY_H__

#include <stddef.h>
#include <ext.h>

struct array {
	void *data;
	size_t num_elem; // Current length
	size_t max_elem; // Maximum length
	size_t elem_size;
};

int array_init(struct array *res, size_t size);

int array_push(struct array *, void *);

int array_push_unique(struct array *arr, void *data);

void array_free(struct array *);

struct array array_null();

void array_erase(struct array *arr, size_t idx);

void *array_get_void(struct array *arr, size_t idx);

#define array_get(arr, idx, type) ((type *)array_get_void(arr, idx))

int array_clear(struct array *arr);

int array_clone(struct array *res, struct array *arr);

#define array_for(pos, arr)                   \
	for (pos = ((typeof(pos))(arr.data)); \
	     pos < (typeof(pos))(arr.data) + arr.num_elem; pos++)

#define INIT_ARRAY(type) array_init(sizeof(type))

#endif
