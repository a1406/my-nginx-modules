#include "mybuf.h"

mybuf_t *alloc_mybuf(ngx_pool_t *pool, size_t size)
{
	mybuf_t *ret = ngx_pcalloc(pool, sizeof(mybuf_t) + size);
	ret->size = size;
	return ret;
}


void my_append_str(ngx_pool_t *pool, const ngx_str_t *str, mybuf_t *mybuf)
{
	mybuf_t *last = mybuf;
	while (mybuf_empty(last) && last->next)
	{
		last = last->next;
	}

	int buf_len = mybuf_len(last);
	int left = str->len - buf_len;
	if (left < 0)
	{
		memcpy(&(last->buf[last->used]), str->data, str->len);
		last->used += str->len;
		return;
	}

	memcpy(&(last->buf[last->used]), str->data, buf_len);
	last->used = last->size;

	int new_size = MYDEFAULT_BUF_SIZE;
	if (left > new_size)
		new_size = left;
	mybuf_t *new_buf = alloc_mybuf(pool, new_size);
	last->next       = new_buf;
	memcpy(&(new_buf->buf[0]), &(str->data[buf_len]), left);
	new_buf->used = left;
	return;
}
