#include <stdio.h>
#include "mybuf.h"

void print_mybuf(mybuf_t *h)
{
	int total_len = 0;
	mybuf_t *buf = h;
	while(buf)
	{
		int len = buf->used;
		total_len += len;
		buf = buf->next;
	}
	char *data = (char *)malloc(total_len + 1);
	data[total_len - 1] = 0;

	buf = h;
	int start = 0;
	while(buf)
	{
		int len = buf->used;
		memcpy(&data[start], buf->buf, len);
		buf = buf->next;
		start += len;
	}

	printf("%s", data);
}

int main(int argc, char *argv[])
{
	mybuf_t *head =( mybuf_t *)ngx_pcalloc(NULL, sizeof(mydefaultbuf_t));
	MY_APPEND_STR(NULL, "1234567", head);
	MY_APPEND_STR(NULL, "abcdefg", head);
	MY_APPEND_STR(NULL, "A", head);
	MY_APPEND_STR(NULL, "", head);
	MY_APPEND_STR(NULL, "BC", head);
	MY_APPEND_STR(NULL, "DEF", head);
	MY_APPEND_STR(NULL, "GHI\n", head);

	print_mybuf(head);

	
	return 0;
}
