#include "array.h"
#include <stdlib.h>
#include <string.h>

void *__malloc(size_t size) {
    return malloc(size);
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

void array_free(struct array *arr) {
    __free(arr);
}
