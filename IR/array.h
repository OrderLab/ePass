#ifndef __ARRAY_H__
#define __ARRAY_H__

#include <stddef.h>
#include <stddef.h>

struct array {
    void  *data;
    size_t num_elem;  // Current length
    size_t max_elem;  // Maximum length
    size_t elem_size;
};

struct array array_init(size_t);
void         array_push(struct array *, void *);
void         array_free(struct array *);
struct array array_null();
void        *__malloc(size_t size);
void         __free(void *ptr);

#endif
