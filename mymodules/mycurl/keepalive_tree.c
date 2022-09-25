#include "keepalive_tree.h"
#include "ngx_core.h"

#include <stddef.h>
#include <assert.h>
#define UNUSED(x) (void)(x)

#define container_of(ptr, type, member) ({ \
                const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type,member) );})

static ngx_rbtree_t rbtree;
ngx_rbtree_node_t   sentinel;

static void
ngx_mycurl_keepalive_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

int ngx_keepalive_tree_init()
{
	ngx_rbtree_init(&rbtree, &sentinel, ngx_mycurl_keepalive_insert_value);
	return 0;
}

static ngx_int_t cmp_conn_data(testcurl_conn_data *a, testcurl_conn_data *b)
{
	// if (a->port == b->port &&
	//     a->host.len == b->host.len &&
	//     ngx_memcmp(a->host.data, b->host.data, a->host.len) == 0)
	// 	return NGX_OK;

	return ngx_cmp_sockaddr(&a->sockaddr.sockaddr, a->socklen,
	                        &b->sockaddr.sockaddr, b->socklen, 1);
}

static void
ngx_mycurl_keepalive_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
	ngx_int_t               rc;
	testcurl_conn_data     *data, *datat;
	ngx_rbtree_node_t     **p;
	ngx_mycurl_keepalive_t *udp, *udpt;

	UNUSED(data);
	UNUSED(datat);	

	for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            udp = (ngx_mycurl_keepalive_t *) node;
            data = &udp->data;

            udpt = (ngx_mycurl_keepalive_t *) temp;
            datat = &udpt->data;

			rc = cmp_conn_data(data, datat);
            // rc = ngx_cmp_sockaddr(c->sockaddr, c->socklen,
            //                       ct->sockaddr, ct->socklen, 1);

            // if (rc == 0 && c->listening->wildcard) {
            //     rc = ngx_cmp_sockaddr(c->local_sockaddr, c->local_socklen,
            //                           ct->local_sockaddr, ct->local_socklen, 1);
            // }

            p = (rc < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


__attribute_maybe_unused__ ngx_int_t
ngx_insert_mycurl_keepalive(testcurl_conn_data *data)
{
    uint32_t               hash;

	ngx_mycurl_keepalive_t *node = container_of(data, ngx_mycurl_keepalive_t, data);

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char *) &data->sockaddr, data->socklen);

    ngx_crc32_final(hash);

    node->node.key = hash;

    ngx_rbtree_insert(&rbtree, &node->node);

    return NGX_OK;
}


__attribute_maybe_unused__ void ngx_delete_mycurl_keepalive(testcurl_conn_data *data)
{
	ngx_mycurl_keepalive_t *node = container_of(data, ngx_mycurl_keepalive_t, data);	
    ngx_rbtree_delete(&rbtree, &node->node);
}


__attribute_maybe_unused__ testcurl_conn_data *
    ngx_lookup_mycurl_keepalive(struct sockaddr *sockaddr, socklen_t socklen)
{
	uint32_t               hash;
    ngx_int_t              rc;
    ngx_rbtree_node_t     *node, *sentinel;

	ngx_mycurl_keepalive_t *udp;

    node = rbtree.root;
    sentinel = rbtree.sentinel;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char *) sockaddr, socklen);

    ngx_crc32_final(hash);

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        udp = (ngx_mycurl_keepalive_t *) node;

        rc = ngx_cmp_sockaddr(sockaddr, socklen,
                              &udp->data.sockaddr.sockaddr, udp->data.socklen, 1);

        if (rc == 0) {
            return &udp->data;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

int ngx_keepalive_tree_ut()
{
	static char *test_init_uri[] = {
		"127.0.0.1:9090/lua_test4?a=111&b=22",
		"127.0.0.1:9091/lua_test4?a=111&b=22",
		"127.0.0.2:9090/lua_test4?a=111&b=22",
		"127.0.0.3:9090/lua_test4?a=111&b=22",
		"12.0.0.1:9090/lua_test4?a=111&b=22",
		"27.0.0.1:9090/lua_test4?a=111&b=22",
		"127.4.0.1:9090/lua_test4?a=111&b=22",
		"127.14.0.1:9090/lua_test4?a=111&b=22",
		"127.4.20.1:9090/lua_test4?a=111&b=22",
		"27.4.0.1:9090/lua_test4?a=111&b=22",
		"173.4.0.1:9090/lua_test4?a=111&b=22",
		"19.34.20.1:9090/lua_test4?a=111&b=22",
	};

	static char *test_find_uri[] = {
		"133.0.0.1:9090/lua_test4?a=111&b=22",
		"127.0.0.5:9091/lua_test4?a=111&b=22",
		"127.1.1.2:9090/lua_test4?a=111&b=22",
		"127.0.0.33:9090/lua_test4?a=111&b=22",
		"112.0.0.1:9090/lua_test4?a=111&b=22",
		"27.30.0.1:9090/lua_test4?a=111&b=22",
		"127.14.10.1:9090/lua_test4?a=111&b=22",
		"127.14.0.11:9090/lua_test4?a=111&b=22",
		"17.4.20.1:9090/lua_test4?a=111&b=22",
		"17.4.10.1:9090/lua_test4?a=111&b=22",
		"173.4.10.11:9090/lua_test4?a=111&b=22",
		"19.34.20.1:9080/lua_test4?a=111&b=22",
	};
	static ngx_mycurl_keepalive_t **test_node;
	
    ngx_log_t *log = ngx_log_init(NULL, NULL);		
	ngx_pool_t *pool = ngx_create_pool(128, log);	
	ngx_url_t u;

	size_t num = sizeof(test_init_uri) / sizeof(test_init_uri[0]);
	test_node = ngx_pcalloc(pool, sizeof(void *) * num);

	for (size_t i = 0; i < num; ++i)
	{
		ngx_memzero(&u, sizeof(ngx_url_t));
		u.url.len  = strlen(test_init_uri[i]);
		u.url.data = (u_char *)test_init_uri[i];
		u.uri_part = 1;
		u.default_port = 80;
		ngx_parse_url(pool, &u);

		test_node[i] = ngx_pcalloc(pool, sizeof(ngx_mycurl_keepalive_t));
		testcurl_conn_data *data = &test_node[i]->data;
		memcpy(&data->sockaddr, &u.sockaddr, sizeof(u.sockaddr));
		data->socklen = u.socklen;

		ngx_insert_mycurl_keepalive(data);
	}

	for (size_t i = 0; i < num; ++i)
	{
		ngx_memzero(&u, sizeof(ngx_url_t));
		u.url.len  = strlen(test_init_uri[i]);
		u.url.data = (u_char *)test_init_uri[i];
		u.uri_part = 1;
		u.default_port = 80;
		ngx_parse_url(pool, &u);

		testcurl_conn_data *data = ngx_lookup_mycurl_keepalive(&u.sockaddr.sockaddr,
			u.socklen);
		assert(data == &test_node[i]->data);
	}	
	for (size_t i = 0; i < num; ++i)
	{
		ngx_memzero(&u, sizeof(ngx_url_t));
		u.url.len  = strlen(test_find_uri[i]);
		u.url.data = (u_char *)test_find_uri[i];
		u.uri_part = 1;
		u.default_port = 80;
		ngx_parse_url(pool, &u);

		testcurl_conn_data *data = ngx_lookup_mycurl_keepalive(&u.sockaddr.sockaddr,
			u.socklen);
		assert(data == NULL);
	}	

	for (size_t i = 0; i < num; ++i)
	{
		ngx_memzero(&u, sizeof(ngx_url_t));
		u.url.len  = strlen(test_init_uri[i]);
		u.url.data = (u_char *)test_init_uri[i];
		u.uri_part = 1;
		u.default_port = 80;
		ngx_parse_url(pool, &u);

		ngx_delete_mycurl_keepalive(&test_node[i]->data);
		
		testcurl_conn_data *data = ngx_lookup_mycurl_keepalive(&u.sockaddr.sockaddr,
			u.socklen);
		assert(data == NULL);
	}	
	
	ngx_destroy_pool(pool);
	return 0;	
}
