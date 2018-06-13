#include <uk/alloc.h>

void *sys_malloc(size_t size)
{
	return uk_malloc(uk_alloc_get_default(), size);
}

void *sys_calloc(int num, size_t size)
{
	return uk_calloc(uk_alloc_get_default(), num, size);
}

void sys_free(void *ptr)
{
	uk_free(uk_alloc_get_default(), ptr);
}
