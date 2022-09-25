#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_core_module.h"
#include "llhttp/llhttp.h"
#include "mybuf.h"

// #include <curl/curl.h>
#include <assert.h>
#include <stdbool.h>

// request->c->data = conn_data;
// conn_data->request_c = c;
// conn_data->parser.data = conn_data;

#define UNUSED(x) (void)(x)

#define APPEND_STR  ("return from test curl\r\n")


typedef struct
{
	ngx_int_t use_testcurl;
} ngx_http_use_testcurl_loc_conf_t;

#define SEND_BUF (mybuf_t *)(&conn_data->send_buf)
#define RECV_BUF (mybuf_t *)(&conn_data->recv_buf)
#define BODY_BUF (mybuf_t *)(&conn_data->body_buf)

typedef enum
{
	CONN_DATA_FINISH_INIT,
	CONN_DATA_FINISH_HEAD,
	CONN_DATA_FINISH_BODY,
	CONN_DATA_FINISH_KEEPALIVE,
} CONN_DATA_FINISH;

typedef struct testcurl_conn_data_s
{
	struct testcurl_conn_data_s *next;

	ngx_str_t           addr_name;
	ngx_connection_t   *c;
	ngx_http_request_t *request;

	mybuf_t        send_buf;
	u_char         pack_send_buf__[MYDEFAULT_BUF_SIZE];
	mybuf_t        recv_buf;
	u_char         pack_recv_buf__[MYDEFAULT_BUF_SIZE];
	mybuf_t        body_buf;
	u_char         pack_body_buf__[MYDEFAULT_BUF_SIZE];
	int            finished;

	llhttp_t          parser;
	llhttp_settings_t settings;

		//for keepalive
	ngx_str_t host;
	in_port_t port;
} testcurl_conn_data;

typedef struct
{
	testcurl_conn_data *head;
} testcurl_ctx_t;

// 嫌麻烦，随便搞个链表，主要是试一下keepalive
typedef struct
{
	testcurl_conn_data *head;	
} testcurl_cache_t;
__attribute_maybe_unused__ static testcurl_cache_t keepalive_cache;

__attribute_maybe_unused__ static int add_to_keepalive_cache(testcurl_conn_data *node)
{
	if (node->finished != CONN_DATA_FINISH_BODY)
		return -1;

	node->next = keepalive_cache.head;	
		//todo addr_name
	node->request = NULL;
	ngx_memzero(&node->send_buf, (sizeof(mybuf_t) + MYDEFAULT_BUF_SIZE) * 3);
	node->finished = CONN_DATA_FINISH_KEEPALIVE;
	llhttp_reset(&node->parser);

	keepalive_cache.head = node;
	return (0);
}
__attribute_maybe_unused__ static testcurl_conn_data * get_from_keepalive_cache(ngx_str_t *addr, in_port_t port)
{
	testcurl_conn_data *head = keepalive_cache.head;
	testcurl_conn_data *pre = NULL;
	while (head)
	{
		if (head->port == port &&
			head->host.len == addr->len &&
			ngx_memcmp(head->host.data, addr->data, addr->len) == 0)
		{
			if (pre)
				pre->next = head->next;
			else
				keepalive_cache.head = head->next;

			head->next = NULL;
			head->finished = CONN_DATA_FINISH_INIT;
			return head;
		}
		pre = head;
		head = head->next;
	}
	return (NULL);
}

static void generate_send_buf(testcurl_conn_data *conn_data);
static int init_parse_http_resp(llhttp_t *parser, llhttp_settings_t *settings);
__attribute_maybe_unused__ static testcurl_conn_data *add_conn_data(ngx_http_request_t *r, testcurl_ctx_t *ctx)
{
	testcurl_conn_data **node = &ctx->head;
	while (*node)
	{
		node = &((*node)->next);
	}
	*node = ngx_pcalloc(r->pool, sizeof(testcurl_conn_data));
	(*node)->request = r;
	r->main->count++;
	(*node)->send_buf.size = MYDEFAULT_BUF_SIZE;
	(*node)->recv_buf.size = MYDEFAULT_BUF_SIZE;
	(*node)->body_buf.size = MYDEFAULT_BUF_SIZE;

	init_parse_http_resp(&((*node)->parser), &((*node)->settings));
	(*node)->parser.data = (*node);
	
	return *node;
}

static char *ngx_set_testcurl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_testcurl_commands[] = {
	{
		ngx_string("testcurl"),
		NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_set_testcurl,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_use_testcurl_loc_conf_t, use_testcurl),
		NULL
	},
	ngx_null_command
};

static ngx_int_t ngx_http_testcurl_init(ngx_conf_t *cf);
static void *ngx_http_testcurl_create_loc_conf(ngx_conf_t *cf);
static ngx_http_module_t ngx_http_testcurl_module_ctx = {
    NULL,          /* preconfiguration */
    ngx_http_testcurl_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_testcurl_create_loc_conf, /* create location configuration */
    NULL  /* merge location configuration */
};

ngx_int_t init_testcurl_process(ngx_cycle_t *cycle);
ngx_module_t ngx_http_testcurl_module = {
    NGX_MODULE_V1,
    &ngx_http_testcurl_module_ctx, /* module context */
    ngx_http_testcurl_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    init_testcurl_process,         /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/* Clean up the SockInfo structure */
// static void remsock(SockInfo *f, GlobalInfo *g)
// {
// 	if (f)
// 	{
// 		if (f->sockfd)
// 		{
//         // if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
// 			if (epoll_ctl(g->epfd, EPOLL_CTL_DEL, f->sockfd, NULL))
// 				fprintf(stderr, "EPOLL_CTL_DEL failed for fd: %d : %s\n",
// 				        f->sockfd, strerror(errno));
// 		}
// 		free(f);
// 	}
// }

// static void setsock(SockInfo *f, curl_socket_t s, CURL *e, int act,
//                     GlobalInfo *g)
// {
// 	struct epoll_event ev;
// 	int                kind = ((act & CURL_POLL_IN) ? EPOLLIN : 0) |
// 	           ((act & CURL_POLL_OUT) ? EPOLLOUT : 0);

// 	if (f->sockfd)
// 	{
// 		if (epoll_ctl(g->epfd, EPOLL_CTL_DEL, f->sockfd, NULL))
// 			fprintf(stderr, "EPOLL_CTL_DEL failed for fd: %d : %s\n",
// 			        f->sockfd, strerror(errno));
// 	}

// 	f->sockfd = s;
// 	f->action = act;
// 	f->easy   = e;

// 	ev.events  = kind;
// 	ev.data.fd = s;
//     // if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
// 	if (epoll_ctl(g->epfd, EPOLL_CTL_ADD, s, &ev))
// 		fprintf(stderr, "EPOLL_CTL_ADD failed for fd: %d : %s\n",
// 		        s, strerror(errno));
// }

/* Initialize a new SockInfo structure */
// static void addsock(curl_socket_t s, CURL *easy, int action, GlobalInfo *g)
// {
//   SockInfo *fdp = (SockInfo*)calloc(1, sizeof(SockInfo));

//   fdp->global = g;
//   setsock(fdp, s, easy, action, g);
//   curl_multi_assign(g->multi, s, fdp);
// }
// static int sock_cb(CURL *e, curl_socket_t s, int what, void *cbp, void *sockp)
// {
// 	GlobalInfo *g         = (GlobalInfo *)cbp;
// 	SockInfo   *fdp       = (SockInfo *)sockp;
// 	const char *whatstr[] = {"none", "IN", "OUT", "INOUT", "REMOVE"};

// 	fprintf(MSG_OUT,
// 	        "socket callback: s=%d e=%p what=%s ", s, e, whatstr[what]);
// 	if (what == CURL_POLL_REMOVE)
// 	{
// 		fprintf(MSG_OUT, "\n");
// 		remsock(fdp, g);
// 	}
// 	else
// 	{
// 		if (!fdp)
// 		{
// 			fprintf(MSG_OUT, "Adding data: %s\n", whatstr[what]);
// 			addsock(s, e, what, g);
// 		}
// 		else
// 		{
// 			fprintf(MSG_OUT,
// 			        "Changing action from %s to %s\n",
// 			        whatstr[fdp->action], whatstr[what]);
// 			setsock(fdp, s, e, what, g);
// 		}
// 	}
// 	return 0;
// }


// static CURLM *g_curl;
ngx_int_t init_testcurl_process(ngx_cycle_t *cycle)
{
	// assert(g_curl == NULL);
	// g_curl = curl_multi_init();

	// curl_multi_setopt(g.multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
	// curl_multi_setopt(g.multi, CURLMOPT_SOCKETDATA, &g);
	// curl_multi_setopt(g.multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
	// curl_multi_setopt(g.multi, CURLMOPT_TIMERDATA, &g);

	return NGX_OK;	
}

static ngx_int_t ngx_http_testcurl_handler(ngx_http_request_t *r);
static char *ngx_set_testcurl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char *rv = NULL;
	ngx_http_core_loc_conf_t *clcf;
	
	rv = ngx_conf_set_flag_slot(cf, cmd, conf);
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_testcurl_handler;
	return rv;
}

static void *ngx_http_testcurl_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_use_testcurl_loc_conf_t *local_conf = NULL;

	local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_use_testcurl_loc_conf_t));
	if (local_conf == NULL)
	{
		return NULL;
	}

	local_conf->use_testcurl = NGX_CONF_UNSET;

	return local_conf;
}

static ngx_int_t ngx_http_testcurl_init(ngx_conf_t *cf)
{
	// ngx_http_handler_pt       *h;
	// ngx_http_core_main_conf_t *cmcf;

	// cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	// h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	// if (h == NULL)
	// {
	// 	return NGX_ERROR;
	// }

	// *h = ngx_http_testcurl_handler;
	return NGX_OK;
}

static ngx_int_t ngx_http_testcurl_connect(ngx_http_request_t *r, testcurl_conn_data *conn_data)
{
	int               rc, type, value;
	ngx_socket_t      s;
	ngx_event_t      *rev, *wev;
	ngx_connection_t *c;
	ngx_err_t         err;
	ngx_uint_t        level;
	ngx_int_t         event;

	UNUSED(value);

	ngx_log_t *log = r->connection->log;
	ngx_url_t u;
	{
		ngx_memzero(&u, sizeof(ngx_url_t));
		// ngx_str_set(&u.url, "127.0.0.1:8011");
		u.url.len      = conn_data->addr_name.len;
		u.url.data     = conn_data->addr_name.data;
		// u.listen       = 1;
		u.uri_part = 1;
		u.default_port = 80;
		if (ngx_parse_url(r->pool, &u) != NGX_OK)
		{
			if (u.err)
			{
				ngx_log_error(NGX_LOG_EMERG, log, 0,
				                   "%s in \"%V\" of the \"listen\" directive",
				                   u.err, &u.url);
			}

			return NGX_ERROR;
		}
	}

	type = SOCK_STREAM;
	s    = ngx_socket(u.family, type, 0);
	ngx_log_debug2(NGX_LOG_DEBUG_EVENT, log, 0, "%s socket %d",
	               (type == SOCK_STREAM) ? "stream" : "dgram", s);
    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }
    c = ngx_get_connection(s, log);
    if (c->pool == NULL) {
        c->pool = ngx_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            // ngx_http_upstream_finalize_request(r, u,
            //                                    NGX_HTTP_INTERNAL_SERVER_ERROR);
			goto failed;
        }
    }
	
	conn_data->c = c;
    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NGX_ERROR;
    }
    c->type = type;
    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        goto failed;
    }
    if (type == SOCK_STREAM) {
        c->recv = ngx_recv;
        c->send = ngx_send;
        c->recv_chain = ngx_recv_chain;
        c->send_chain = ngx_send_chain;
        c->sendfile = 1;
    } else { /* type == SOCK_DGRAM */
        c->recv = ngx_udp_recv;
        c->send = ngx_send;
        c->send_chain = ngx_udp_send_chain;
    }
    c->log_error = 1;
    rev = c->read;
    wev = c->write;

    rev->log = log;
    wev->log = log;
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->start_time = ngx_current_msec;
    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
            goto failed;
        }
    }
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                   "connect to %V, fd:%d #%uA", &conn_data->addr_name, s, c->number);
	
	generate_send_buf(conn_data);

    rc = connect(s, &u.sockaddr.sockaddr, u.socklen);
    // rc = connect(s, NULL, u.socklen);	
    if (rc == -1) {
        err = ngx_socket_errno;
        if (err != NGX_EINPROGRESS)
		{
            if (err == NGX_ECONNREFUSED
#if (NGX_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == NGX_EAGAIN
#endif
                || err == NGX_ECONNRESET
                || err == NGX_ENETDOWN
                || err == NGX_ENETUNREACH
                || err == NGX_EHOSTDOWN
                || err == NGX_EHOSTUNREACH)
            {
                level = NGX_LOG_ERR;

            } else {
                level = NGX_LOG_CRIT;
            }

            ngx_log_error(level, c->log, err, "connect() to %V failed",
                          	&conn_data->addr_name);

            ngx_close_connection(c);
			conn_data->c = NULL;

            return NGX_DECLINED;
        }
	}
    if (ngx_add_conn) {
        if (rc == -1) {

            /* NGX_EINPROGRESS */

            return NGX_AGAIN;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, log, 0, "connected");

        wev->ready = 1;

        return NGX_OK;
    }
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue */

        event = NGX_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = NGX_LEVEL_EVENT;
    }
    if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
        goto failed;
    }
    if (rc == -1) {

        /* NGX_EINPROGRESS */

        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
            goto failed;
        }

        return NGX_AGAIN;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, log, 0, "connected");

    wev->ready = 1;

    return NGX_OK;
failed:

    ngx_close_connection(c);
	conn_data->c = NULL;
	return NGX_ERROR;
	
}

static int ngx_testcurl_send(testcurl_conn_data *conn_data)//ngx_connection_t *c, u_char *buf, int buflen)
{
	ngx_connection_t *c = conn_data->c;
	mybuf_t *buf = SEND_BUF;
	while(buf)
	{
		int buflen = buf->used - buf->start;
		if (buflen > 0)
		{
			u_char *buf_ = &buf->buf[buf->start];
			int     n    = c->send(c, buf_, buflen);
			if (n == NGX_AGAIN)
			{
				if (ngx_handle_write_event(c->write, 0) != NGX_OK)
				{
					// TODO:
					printf("%d: hanle write event failed\n", __LINE__);					
					c->error = 1;
					return -1;
				}
				return 0;
			}
			if (n == NGX_ERROR)
			{
				// TODO:
				printf("%d: send n == NGX_ERROR failed\n", __LINE__);
				c->error = 1;
				// u->socket_errno = ngx_socket_errno;
				return n;
			}
			if (n == 0)
			{
				// TODO:
				printf("%d: send n == 0\n", __LINE__);				
				c->error = 1;
				// u->socket_errno = ngx_socket_errno;
				return n;
			}
			if (n < 0)
			{
				// TODO:
				printf("%d: send n < 0\n", __LINE__);								
				c->error = 1;
				// u->socket_errno = ngx_socket_errno;
				return n;
			}
			buf->start += n;
			if (n < buflen)
			{
				if (ngx_handle_write_event(c->write, 0) != NGX_OK)
				{
					// TODO:
					printf("%d: hanle write event failed\n", __LINE__);
					c->error = 1;
					return -1;
				}
				return 0;
			}
		}
		buf = buf->next;
	}
	return 0;
}

static bool check_all_conn_data_finished(ngx_http_request_t *r)
{
	testcurl_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_testcurl_module);
	assert(ctx);

	testcurl_conn_data *head = ctx->head;
	while(head)
	{
		if (head->finished != CONN_DATA_FINISH_BODY)
			return false;
		head = head->next;
	}

	return true;
}

static void testcurl_send_resp(ngx_http_request_t *r);
static int ngx_testcurl_recv(testcurl_conn_data *conn_data)
{
	ngx_connection_t *c = conn_data->c;
	for (;;)
	{
		u_char  *p;
		int      len;
		mybuf_t *buf = get_recv_buf(conn_data->c->pool, &conn_data->recv_buf, &p, &len);
		int      n   = c->recv(c, p, len);
		if (n > 0)
		{
			llhttp_t         *parser = &conn_data->parser;
			enum llhttp_errno err    = llhttp_execute(parser, (char *)p, n);
			if (err == HPE_OK)
			{
				/* Successfully parsed! */
				int ret = llhttp_message_needs_eof(parser);
				UNUSED(ret);
				llhttp_errno_t ret2 = llhttp_finish(parser);
				UNUSED(ret2);
				const char *errmsg = llhttp_errno_name(ret2);
				if (ret2 != HPE_INVALID_EOF_STATE && ret2 != HPE_OK)
				{
					printf("http finish: %s\n", errmsg);
					// c->error = 1;
					// return;
				}
			}
			else
			{
				fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err),
				        parser->reason);
				c->error = 1;
				return 0;
			}
			buf->used += n;
			continue;
		}
		if (n == NGX_AGAIN)
		{
			if (ngx_handle_read_event(c->read, 0) != NGX_OK)
			{
				// TODO:
				printf("handle read event failed\n");
				c->error = 1;
				return 0;
			}
			break;
		}
		if (n == NGX_ERROR)
		{
			// TODO:
			printf("n == NGX_ERROR\n");
			c->error = 1;
			return 0;
		}
		if (n == 0)
		{
			printf("n == 0, close connection\n");
			ngx_http_close_connection(c);

			// ngx_int_t event;
			// if (ngx_event_flags & NGX_USE_CLEAR_EVENT)
			// {
			// 	/* kqueue */
			// 	event = NGX_CLEAR_EVENT;
			// }
			// else
			// {
			// 	/* select, poll, /dev/poll */
			// 	event = NGX_LEVEL_EVENT;
			// }
			// ngx_del_event(
			return 0;
		}
		break;
	}

//	if (conn_data->finished == CONN_DATA_FINISH_BODY)
	if (check_all_conn_data_finished(conn_data->request))
	{
		testcurl_send_resp(conn_data->request);
		ngx_http_close_connection(c);
	}
	return 0;
}

static int handle_on_headers_complete(llhttp_t* llhttp)
{
	// printf("head complete\n");
	testcurl_conn_data *conn_data = llhttp->data;
	conn_data->finished = CONN_DATA_FINISH_HEAD;
	return (HPE_OK);	
}
static int handle_on_message_complete(llhttp_t* llhttp)
{
	// printf("body complete\n");
	testcurl_conn_data *conn_data = llhttp->data;	
	conn_data->finished = CONN_DATA_FINISH_BODY;	
	return (HPE_OK);	
}

static int handle_on_url(llhttp_t* llhttp, const char *at, size_t length)
{
	return (HPE_OK);		
}
static int handle_on_status(llhttp_t* llhttp, const char *at, size_t length)
{
	return (HPE_OK);		
}
static int handle_on_header_field(llhttp_t* llhttp, const char *at, size_t length)
{
	return (HPE_OK);		
}
static int handle_on_header_value(llhttp_t* llhttp, const char *at, size_t length)
{
	return (HPE_OK);		
}
static int handle_on_body(llhttp_t* llhttp, const char *at, size_t length)
{
	testcurl_conn_data *conn_data = llhttp->data;
	ngx_str_t t__;
	t__.data = (u_char *)at;
	t__.len  = length;
	my_append_str(conn_data->c->pool, &t__, BODY_BUF);
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

	// enum llhttp_errno err = llhttp_execute(&parser, (const char *)readbuf, n);
	// if (err == HPE_OK)
	// {
	// 	/* Successfully parsed! */
	// 	int ret = llhttp_message_needs_eof(&parser);
	// 	UNUSED(ret);
	// 	llhttp_errno_t ret2 = llhttp_finish(&parser);
	// 	UNUSED(ret2);
	// 	const char* errmsg = llhttp_errno_name(ret2);
	// 	printf("%s\n", errmsg);
	// }
	// else
	// {
	// 	fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err),
	// 	        parser.reason);
	// }
	return (0);
}

__attribute_maybe_unused__ int send_header_if_needed(ngx_http_request_t *r)
{
	ngx_int_t rc;

	if (!r->header_sent)
	{
		if (r->headers_out.status == 0)
		{
			r->headers_out.status = NGX_HTTP_OK;
		}

		if (ngx_http_set_content_type(r) != NGX_OK)
		{
			return NGX_ERROR;
		}

		ngx_http_clear_content_length(r);
		ngx_http_clear_accept_ranges(r);


		rc = ngx_http_send_header(r);
		// ctx->header_sent = 1;
		return rc;
	}
	return NGX_OK;
}

__attribute_maybe_unused__ static void generate_send_buf(testcurl_conn_data *conn_data)
{
	// GET /path1/path2/command?a=22&b=44 HTTP/1.1
	// Host: localhost:9090
	// User-Agent: curl/7.85.0
	// Accept: */*

	// "GET /lua_test4?a=111&b=22 HTTP/1.1\r\n"
	// "Host: localhost:9090\r\n"
	// "User-Agent: curl/7.85.0\r\n"
	// "Accept: */*\r\n"
	// "\r\n";

	ngx_pool_t *pool = conn_data->c->pool;
	const ngx_str_t *url = &conn_data->addr_name;
	char *p = ngx_strchr(url->data, '/');
	if (!p)
	{
		ngx_str_t t;
		ngx_str_set(&t, "GET / HTTP/1.1\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));

		ngx_str_set(&t, "Host: ");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));		
		my_append_str(pool, &conn_data->addr_name, (mybuf_t *)&(conn_data->send_buf));
		ngx_str_set(&t, "\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));		

		ngx_str_set(&t, "User-Agent: curl/7.85.0\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));

		ngx_str_set(&t, "Accept: */*\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));

		ngx_str_set(&t, "\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));
	}
	else
	{
		ngx_str_t t;
		ngx_str_set(&t, "GET ");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));
		t.data = (u_char *)p;
		t.len = &url->data[url->len] - (u_char *)p;
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));		
		ngx_str_set(&t, " HTTP/1.1\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));

		ngx_str_set(&t, "Host: ");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));		
		t.data = url->data;
		t.len = (u_char *)p - url->data;
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));
		ngx_str_set(&t, "\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));		

		ngx_str_set(&t, "User-Agent: curl/7.85.0\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));

		ngx_str_set(&t, "Accept: */*\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));

		ngx_str_set(&t, "\r\n");
		my_append_str(pool, &t, (mybuf_t *)&(conn_data->send_buf));
	}
}

static void testcurl_send_resp(ngx_http_request_t *r)
{
	ngx_http_complex_value_t cv;
	ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

	testcurl_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_testcurl_module);
	assert(ctx);
	size_t retsize = sizeof(APPEND_STR) - 1;
	testcurl_conn_data *head = ctx->head;
	while (head)
	{
		size_t body_len = get_buf_len(&head->body_buf);
		retsize += body_len;
		head = head->next;
	}
	char *retvalue = ngx_pcalloc(r->pool, retsize);
	
	int i = 0;
	head = ctx->head;
	while (head)
	{
		int ret = get_buf_data(&head->body_buf, &retvalue[i]);
		assert(ret >= 0);
		i += ret;
		head = head->next;
	}

	// size_t body_len = get_buf_len(&head->body_buf);
	// size_t retsize  = body_len + sizeof(APPEND_STR) - 1;
	// char  *retvalue = ngx_pcalloc(r->pool, retsize);
	// get_buf_data(&head->body_buf, retvalue);
	
	memcpy(&retvalue[i], APPEND_STR, sizeof(APPEND_STR) - 1);
	// u_char retvalue[] = "return from test curl\r\n";
	cv.value.len  = retsize;
	cv.value.data = (u_char *)retvalue;

	// int sendheadret = 0;
	// sendheadret = send_header_if_needed(r);


	if (r->headers_out.status == 0)
	{
		r->headers_out.status = NGX_HTTP_OK;
	}

	if (ngx_http_set_content_type(r) != NGX_OK)
	{
		// return NGX_ERROR;
		printf("set content type failed\n");
	}

	ngx_http_clear_content_length(r);
	ngx_http_clear_accept_ranges(r);

	r->connection->data = r;
	// int ret = 0, ret2 = 0;
	ngx_http_send_response(r, NGX_HTTP_OK, NULL, &cv);
	// int ret2 = ngx_http_send_special(r, NGX_HTTP_LAST);
	// printf("send http resp, sendheadret = %d, ret = %d, %d\n", sendheadret, ret, ret2);
	ngx_http_finalize_request(r, NGX_OK);
}

static void ngx_testcurl_rwevent_handler(ngx_event_t *ev)
{
	ngx_connection_t   *c = ev->data;
	testcurl_conn_data *conn_data = c->data;
//	ngx_http_request_t *r = conn_data->request;

	if (ev->write == 1)
	{
		ngx_testcurl_send(conn_data);
	}
	else
	{
		ngx_testcurl_recv(conn_data);		
	}
}

static ngx_int_t ngx_http_testcurl_uri(ngx_http_request_t *r, const char *uri)
{
	testcurl_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_testcurl_module);	
	testcurl_conn_data *conn_data = add_conn_data(r, ctx);
	// ngx_str_set(&conn_data->addr_name, uri);
	conn_data->addr_name.data = (u_char *)uri;
	conn_data->addr_name.len = strlen(uri);
	int rc = ngx_http_testcurl_connect(r, conn_data);

	ngx_connection_t *c;	
    c = conn_data->c;

    c->requests++;

    c->data = conn_data;

    c->write->handler = ngx_testcurl_rwevent_handler;
    c->read->handler = ngx_testcurl_rwevent_handler;

    c->sendfile &= r->connection->sendfile;

    if (r->connection->tcp_nopush == NGX_TCP_NOPUSH_DISABLED) {
        c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    }

	assert(c->pool);
    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;
	return rc;
}

static ngx_int_t ngx_http_testcurl_handler(ngx_http_request_t *r)
{
	ngx_http_use_testcurl_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_testcurl_module);
	if (conf->use_testcurl != 1) {
		return NGX_OK;
	}

	testcurl_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(testcurl_ctx_t));
	if (ctx == NULL)
	{
		return NGX_ERROR;
	}
	ngx_http_set_ctx(r, ctx, ngx_http_testcurl_module);

	// ngx_parse_url    //域名解析
    // u->peer.log = r->connection->log;
    // u->peer.log_error = NGX_ERROR_ERR;
	// ngx_event_connect_peer(ngx_peer_connection_t *pc)	;


	int rc = ngx_http_testcurl_uri(r, "127.0.0.1:9090/lua_test4?a=111&b=22");
	ngx_http_testcurl_uri(r, "127.0.0.1:9091/lua_test4?a=9091a&b=9091b");
	
	if (rc == NGX_AGAIN) {
    //     ngx_add_timer(c->write, u->conf->connect_timeout);
    //     return;
		return NGX_DONE;
    }
	
	return NGX_OK;	
}
