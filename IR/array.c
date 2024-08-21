#include "array.h"
#include <stdlib.h>
#include <string.h>

void *__malloc(size_t size) {
    void *data = malloc(size);
    memset(data, 0, size);
    return data;
}

void __free(void *ptr) {
    free(ptr);
}

struct array array_init(size_t size) {
    struct array res;
    res.data      = __malloc(size * 4);
    res.max_elem  = 4;
    res.elem_size = size;
    res.num_elem  = 0;
    return res;
}

struct array array_null() {
    struct array res;
    res.data      = NULL;
    res.max_elem  = 0;
    res.elem_size = 0;
    res.num_elem  = 0;
    return res;
}

void array_push(struct array *arr, void *data) {
    if (arr->num_elem >= arr->max_elem) {
        // Reallocate
        void *new_data = __malloc(arr->max_elem * 2 * arr->elem_size);
        memcpy(new_data, arr->data, arr->num_elem * arr->elem_size);
        __free(arr->data);
        arr->data = new_data;
        arr->max_elem *= 2;
    }
    // Push back
    memcpy((char *)(arr->data) + arr->elem_size * arr->num_elem, data, arr->elem_size);
    arr->num_elem++;
}

void array_push_unique(struct array *arr, void *data) {
    for (size_t i = 0; i < arr->num_elem; ++i) {
        if (memcmp((char *)(arr->data) + arr->elem_size * i, data, arr->elem_size) == 0) {
            return;
        }
    }
    array_push(arr, data);
}

void array_erase(struct array *arr, size_t idx) {
    if (idx >= arr->num_elem) {
        return;
    }
    // Shift elements
    for (size_t i = idx; i < arr->num_elem - 1; ++i) {
        memcpy((char *)(arr->data) + arr->elem_size * i,
               (char *)(arr->data) + arr->elem_size * (i + 1), arr->elem_size);
    }
    arr->num_elem--;
}

void array_clear(struct array *arr) {
    __free(arr->data);
    arr->data     = __malloc(arr->elem_size * 4);
    arr->max_elem = 4;
    arr->num_elem = 0;
}

struct array array_clone(struct array *arr) {
    struct array res;
    res.num_elem  = arr->num_elem;
    res.max_elem  = arr->max_elem;
    res.elem_size = arr->elem_size;
    res.data      = __malloc(arr->max_elem * arr->elem_size);
    memcpy(res.data, arr->data, arr->num_elem * arr->elem_size);
    return res;
}

void array_free(struct array *arr) {
    __free(arr->data);
    *arr = array_null();
}

void *array_get_void(struct array *arr, size_t idx) {
    if (idx >= arr->num_elem) {
        return NULL;
    }
    return (char *)(arr->data) + arr->elem_size * idx;
}
