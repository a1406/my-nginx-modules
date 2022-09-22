#ifndef UT_H
#define UT_H

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

typedef struct
{
} ngx_pool_t;
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);

typedef struct {
    size_t      len;
    u_char     *data;
} ngx_str_t;
#define ngx_string(str)     { sizeof(str) - 1, (u_char *) str }
#define ngx_null_string     { 0, NULL }
#define ngx_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL

#endif /* UT_H */
