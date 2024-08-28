#ifndef __BPF_IR_EXT_H__
#define __BPF_IR_EXT_H__

#include <stddef.h>

void *__malloc(size_t size);

void __free(void *ptr);

#endif
