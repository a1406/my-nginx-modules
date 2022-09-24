#include <stdio.h>
#include "mybuf.h"
#include "llhttp/llhttp.h"

#define UNUSED(x) (void)(x)

size_t test_recv(void *buf, size_t len)
{
//echo -e "GET /lua_test4?a=111&b=22 HTTP/1.1\r\nHost: localhost:9090\r\nUser-Agent: curl/7.85.0\r\nAccept: */*\r\n\r\n" | nc localhost 9090
	
	static char totaldata[] =
	    "HTTP/1.1 200 OK\r\n"
	    "Server: openresty/1.21.4.1\r\n"
	    "Date: Thu, 22 Sep 2022 15:30:40 GMT\r\n"
	    "Content-Type: application/octet-stream\r\n"
	    "Transfer-Encoding: chunked\r\n"
	    "Connection: keep-alive\r\n"
	    "\r\n"
	    "17\r\n"
	    "Hello,world! lua test4\n"
	    "\r\n"
	    "7\r\n"
	    "a: 111\n"
	    "\r\n"
	    "6\r\n"
	    "b: 22\n"
	    "\r\n"
	    "0\r\n"
	    "\r\n";
	static int index = 0;

	size_t datalen = sizeof(totaldata) - 1 - index;
	if (len >= datalen)
	{
		memcpy(buf, &totaldata[index], datalen);
		index += datalen;
		return datalen;
	}

	memcpy(buf, &totaldata[index], len);
	index += len;
	return len;
}

typedef enum
{
	PARSE_PHASE_INIT,	
	PARSE_PHASE_URL,
	PARSE_PHASE_STATUS,
	PARSE_PHASE_HEAD_KEY,
	PARSE_PHASE_HEAD_VALUE,
	PARSE_PHASE_BODY,
} PARSE_PHASE;

const static char *phase_name[] = {
	"PARSE_PHASE_INIT",	
	"PARSE_PHASE_URL",
	"PARSE_PHASE_STATUS",
	"PARSE_PHASE_HEAD_KEY",
	"PARSE_PHASE_HEAD_VALUE",
	"PARSE_PHASE_BODY",
};

static mybuf_t g_last;
static PARSE_PHASE g_phase;
static void print_last_buf(mybuf_t *buf, const char *prefix)
{
	char *t = alloc_buf_data(NULL, buf);
	printf("%s: %s\n", prefix, t);
}

static int handle_on_headers_complete(llhttp_t* llhttp)
{
	print_last_buf(&g_last, phase_name[g_phase]);
	memset(&g_last, 0, sizeof(mybuf_t));
	printf("headers finished\n");
	return (HPE_OK);	
}
static int handle_on_message_complete(llhttp_t* llhttp)
{
	print_last_buf(&g_last, phase_name[g_phase]);
	memset(&g_last, 0, sizeof(mybuf_t));
	printf("message finished\n");
	return (HPE_OK);	
}

static int handle_on_url(llhttp_t* llhttp, const char *at, size_t length)
{
	if (g_phase != PARSE_PHASE_URL)
	{
		print_last_buf(&g_last, phase_name[g_phase]);
		memset(&g_last, 0, sizeof(mybuf_t));
		g_phase = PARSE_PHASE_URL;
	}
	ngx_str_t t__;
	t__.data = (u_char *)at;
	t__.len = length;
	my_append_str(NULL, &t__, &g_last);
	return (HPE_OK);		
}
static int handle_on_status(llhttp_t* llhttp, const char *at, size_t length)
{
	if (g_phase != PARSE_PHASE_STATUS)
	{
		print_last_buf(&g_last, phase_name[g_phase]);
		memset(&g_last, 0, sizeof(mybuf_t));
		g_phase = PARSE_PHASE_STATUS;
	}
	ngx_str_t t__;
	t__.data = (u_char *)at;
	t__.len = length;
	my_append_str(NULL, &t__, &g_last);
	
	return (HPE_OK);		
}
static int handle_on_header_field(llhttp_t* llhttp, const char *at, size_t length)
{
	if (g_phase != PARSE_PHASE_HEAD_KEY)
	{
		print_last_buf(&g_last, phase_name[g_phase]);
		memset(&g_last, 0, sizeof(mybuf_t));
		g_phase = PARSE_PHASE_HEAD_KEY;
	}
	ngx_str_t t__;
	t__.data = (u_char *)at;
	t__.len = length;
	my_append_str(NULL, &t__, &g_last);
	
	return (HPE_OK);		
}
static int handle_on_header_value(llhttp_t* llhttp, const char *at, size_t length)
{
	if (g_phase != PARSE_PHASE_HEAD_VALUE)
	{
		print_last_buf(&g_last, phase_name[g_phase]);
		memset(&g_last, 0, sizeof(mybuf_t));
		g_phase = PARSE_PHASE_HEAD_VALUE;
	}
	ngx_str_t t__;
	t__.data = (u_char *)at;
	t__.len = length;
	my_append_str(NULL, &t__, &g_last);
	
	return (HPE_OK);		
}
static int handle_on_body(llhttp_t* llhttp, const char *at, size_t length)
{
	if (g_phase != PARSE_PHASE_BODY)
	{
		print_last_buf(&g_last, phase_name[g_phase]);
		memset(&g_last, 0, sizeof(mybuf_t));
		g_phase = PARSE_PHASE_BODY;
	}
	ngx_str_t t__;
	t__.data = (u_char *)at;
	t__.len = length;
	my_append_str(NULL, &t__, &g_last);
	
	return (HPE_OK);		
}

static int init_parse_http_resp(llhttp_t *parser, llhttp_settings_t *settings)
{
	// llhttp_t          parser;
	// llhttp_settings_t settings;

	/* Initialize user callbacks and settings */
	llhttp_settings_init(settings);

	/* Set user callback */
	settings->on_headers_complete = handle_on_headers_complete;
	settings->on_message_complete = handle_on_message_complete;
	settings->on_url = handle_on_url;
	settings->on_status = handle_on_status;
	settings->on_header_field = handle_on_header_field;
	settings->on_header_value = handle_on_header_value;
	settings->on_body = handle_on_body;	

	llhttp_init(parser, HTTP_RESPONSE, settings);

	return (0);
}

int main(int argc, char *argv[])
{
	llhttp_t parser;
	llhttp_settings_t settings;	
	init_parse_http_resp(&parser, &settings);
	
	mydefaultbuf_t *head = (mydefaultbuf_t *)ngx_pcalloc(NULL, sizeof(mydefaultbuf_t));
	u_char         *p;

	int len;

	for (;;) {
		mybuf_t *t = get_recv_buf(NULL, head, &p, &len);
		size_t recv_len = test_recv(p, len);
		if (recv_len == 0)
			break;
		t->used += recv_len;

		enum llhttp_errno err = llhttp_execute(&parser, (char *)p, recv_len);
		if (err == HPE_OK)
		{
			/* Successfully parsed! */
			int ret = llhttp_message_needs_eof(&parser);
			UNUSED(ret);
			llhttp_errno_t ret2 = llhttp_finish(&parser);
			UNUSED(ret2);
			const char *errmsg = llhttp_errno_name(ret2);
			if (ret2 != HPE_INVALID_EOF_STATE)
				printf("%d, %s\n", ret, errmsg);
		}
		else
		{
			fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err),
			        parser.reason);
			break;
		}
	}
	printf("recv finished\n");
	return 0;
}
