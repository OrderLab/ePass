#ifndef __BPF_IR_EXT_H__
#define __BPF_IR_EXT_H__

#include <errno.h>
#include <stddef.h>

void *__malloc(size_t size);

void __free(void *ptr);

#define SAFE_MALLOC(dst, size)                     \
	{                                   \
		dst = __malloc(size); \
		if (!dst) {                 \
			return -ENOMEM;     \
		}                           \
	}

#endif
