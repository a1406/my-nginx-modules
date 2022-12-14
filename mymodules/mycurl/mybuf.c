#include "mybuf.h"
#include <assert.h>

mybuf_t *alloc_mybuf(ngx_pool_t *pool, size_t size)
{
	mybuf_t *ret = ngx_pcalloc(pool, sizeof(mybuf_t) + size);
	// mybuf_t *ret = malloc(sizeof(mybuf_t) + size);
	// memset(ret, 0, sizeof(mybuf_t) + size);
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
	if (left <= 0)
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

mybuf_t *get_recv_buf(ngx_pool_t *pool, mybuf_t *head, u_char **p, int *len)
{
	mybuf_t *ret = (mybuf_t *)head;
	while (mybuf_empty(ret) && ret->next)
	{
		assert(ret->size == 1);
		ret = ret->next;
	}
	
	int n = ret->size - ret->used;
	assert(n == 0 || n == 1);
	if (n > 0)
	{
		assert(ret->used == 0);
		*len = n;
		*p = &ret->buf[ret->used];
		return ret;
	}
	mybuf_t *new_buf = alloc_mybuf(pool, MYDEFAULT_BUF_SIZE);
	// printf("alloc_mybuf ret %p\n", new_buf);
	ret->next = new_buf;
	ret = new_buf;

	*len = MYDEFAULT_BUF_SIZE;
	*p = &ret->buf[0];

	assert(ret->size == 1);
	assert(ret->used == 0);
	assert(ret->next == NULL);	
	return ret;
}

size_t get_buf_len(const mybuf_t *buf)
{
	size_t ret = 0;
	while (buf)
	{
		ret += buf->used;
		buf = buf->next;
	}
	return ret;
}
int get_buf_data(const mybuf_t *buf, char *data)
{
	size_t ret = 0;	
	while (buf)
	{
		int len = buf->used;
		ret += len;
		memcpy(data, buf->buf, len);
		data += buf->used;
		buf = buf->next;
	}
	return ret;
}
char *alloc_buf_data(ngx_pool_t *pool, const mybuf_t *buf)
{
	size_t size = get_buf_len(buf);
	char *ret = (char *)ngx_pcalloc(pool, size + 1);
	get_buf_data(buf, ret);
	ret[size] = '\0';
	return ret;
}
