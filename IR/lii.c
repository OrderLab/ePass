#include <linux/bpf_ir.h>

// Kernel-side Low Interface Implementation

void *malloc_proto(size_t size)
{
	return kvzalloc(size, GFP_KERNEL);
}

void free_proto(void *ptr)
{
	kvfree(ptr);
}
