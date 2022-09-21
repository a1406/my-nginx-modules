#include "ut.h"

void *ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
	void *ret = malloc(size);
	memset(ret, 0, size);
	return ret;
}
