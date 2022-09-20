#ifndef MYBUF_H
#define MYBUF_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct mybuf_s
{
	struct mybuf_s *next;
	size_t size;
	size_t used;
	u_char buf[0];
} mybuf_t;

mybuf_t *alloc_mybuf(ngx_pool_t *pool, size_t size);

#define mybuf_max_len(buf) (buf->size)
#define mybuf_len(buf) (buf->size - buf->used)
#define mybuf_empty(buf) (buf->size <= buf->used)

#define MYDEFAULT_BUF_SIZE 1024
typedef struct mydefaultbuf_s
{
	struct mybuf_s *next;
	size_t size;
	size_t used;
	u_char buf[MYDEFAULT_BUF_SIZE];
} mydefaultbuf_t;

void my_append_str(ngx_pool_t *pool, const ngx_str_t *str, mybuf_t *mybuf);

#endif /* MYBUF_H */
