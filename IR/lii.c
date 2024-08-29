// Kernel-side Low Interface Implementation

#include "bpf_ir.h"

void *malloc_proto(size_t size)
{
	return kvzalloc(size, GFP_KERNEL);
}

void free_proto(void *ptr)
{
	kvfree(ptr);
}
