#include <linux/bpf_ir.h>

// Kernel-side Low-level Interface Implementation

#ifdef __KERNEL__

void *malloc_proto(size_t size)
{
	return kvzalloc(size, GFP_KERNEL);
}

void free_proto(void *ptr)
{
	kvfree(ptr);
}
#else

void *malloc_proto(size_t size)
{
	void *data = malloc(size);
	if (data) {
		memset(data, 0, size);
	}
	return data;
}

void free_proto(void *ptr)
{
	free(ptr);
}

#endif
