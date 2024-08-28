// Kernel-side Low Interface Implementation

#include "bpf_ir.h"
#include <linux/sort.h>

void *malloc_proto(size_t size)
{
	// TODO
	return NULL;
}

void free_proto(void *ptr)
{
}

void qsort(void *base, size_t num, size_t size,
	   int (*compar)(const void *, const void *))
{
	sort(base, num, size, compar, NULL);
}
