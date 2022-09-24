#ifndef MYBUF_H
#define MYBUF_H

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct mybuf_s
{
	struct mybuf_s *next;
	size_t          size;
	size_t          used;
	size_t          start;
	u_char          buf[0];
} mybuf_t;

mybuf_t *alloc_mybuf(ngx_pool_t *pool, size_t size);

#define mybuf_max_len(buf) (buf->size)
#define mybuf_len(buf) (buf->size - buf->used)
#define mybuf_empty(buf) (buf->size <= buf->used)

#define MYDEFAULT_BUF_SIZE 1
typedef struct mydefaultbuf_s
{
	struct mybuf_s *next;
	size_t          size;
	size_t          used;
	size_t          start;
	u_char          buf[MYDEFAULT_BUF_SIZE];
} mydefaultbuf_t;

void my_append_str(ngx_pool_t *pool, const ngx_str_t *str, mybuf_t *mybuf);
#define MY_APPEND_STR(pool, str, mybuf) { ngx_str_t t__; ngx_str_set(&t__, str); my_append_str(pool, &t__, mybuf);  }

mybuf_t *get_recv_buf(ngx_pool_t *pool, mydefaultbuf_t *head, u_char **p, int *len);

size_t get_buf_len(const mybuf_t *buf);
void get_buf_data(const mybuf_t *buf, char *data);
char *alloc_buf_data(ngx_pool_t *pool, const mybuf_t *buf);

#endif /* MYBUF_H */
