#ifndef KEEPALIVE_TREE_H
#define KEEPALIVE_TREE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_core_module.h"

#include "mybuf.h"
#include "llhttp/llhttp.h"

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
	ngx_str_t                    host;
	in_port_t                    port;
    socklen_t                 socklen;
    ngx_sockaddr_t            sockaddr;

	//没有timeout，只要对方不关闭就一直用
} testcurl_conn_data;

typedef struct  {
	ngx_rbtree_node_t  node;
	testcurl_conn_data data;
} ngx_mycurl_keepalive_t;


int ngx_keepalive_tree_init();
ngx_int_t ngx_insert_mycurl_keepalive(testcurl_conn_data *data);
void ngx_delete_mycurl_keepalive(testcurl_conn_data *data);
testcurl_conn_data *ngx_lookup_mycurl_keepalive(struct sockaddr *sockaddr, socklen_t socklen);

int ngx_keepalive_tree_ut();

#endif /* KEEPALIVE_TREE_H */
