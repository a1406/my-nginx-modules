#include "keepalive_tree.h"
#include "ngx_core.h"

#define UNUSED(x) (void)(x)

static ngx_rbtree_t      rbtree;
static ngx_rbtree_node_t sentinel;


static ngx_int_t cmp_conn_data(testcurl_conn_data *a, testcurl_conn_data *b)
{
	if (a->port == b->port &&
	    a->host.len == b->host.len &&
	    ngx_memcmp(a->host.data, b->host.data, a->host.len) == 0)
		return NGX_OK;
	return NGX_DECLINED;
}

void
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

#if 0
static ngx_int_t
ngx_insert_mycurl_keepalive(testcurl_conn_data *data)
{
    uint32_t               hash;
    ngx_pool_cleanup_t    *cln;
    ngx_udp_connection_t  *udp;

    if (c->udp) {
        return NGX_OK;
    }

    udp = ngx_pcalloc(c->pool, sizeof(ngx_udp_connection_t));
    if (udp == NULL) {
        return NGX_ERROR;
    }

    udp->connection = c;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char *) c->sockaddr, c->socklen);

    if (c->listening->wildcard) {
        ngx_crc32_update(&hash, (u_char *) c->local_sockaddr, c->local_socklen);
    }

    ngx_crc32_final(hash);

    udp->node.key = hash;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->data = c;
    cln->handler = ngx_delete_udp_connection;

    ngx_rbtree_insert(&c->listening->rbtree, &udp->node);

    c->udp = udp;

    return NGX_OK;
}


void
ngx_delete_udp_connection(void *data)
{
    ngx_connection_t  *c = data;

    if (c->udp == NULL) {
        return;
    }

    ngx_rbtree_delete(&c->listening->rbtree, &c->udp->node);

    c->udp = NULL;
}


static ngx_connection_t *
ngx_lookup_udp_connection(ngx_listening_t *ls, struct sockaddr *sockaddr,
    socklen_t socklen, struct sockaddr *local_sockaddr, socklen_t local_socklen)
{
    uint32_t               hash;
    ngx_int_t              rc;
    ngx_connection_t      *c;
    ngx_rbtree_node_t     *node, *sentinel;
    ngx_udp_connection_t  *udp;

#if (NGX_HAVE_UNIX_DOMAIN)

    if (sockaddr->sa_family == AF_UNIX) {
        struct sockaddr_un *saun = (struct sockaddr_un *) sockaddr;

        if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)
            || saun->sun_path[0] == '\0')
        {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                           "unbound unix socket");
            return NULL;
        }
    }

#endif

    node = ls->rbtree.root;
    sentinel = ls->rbtree.sentinel;

    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char *) sockaddr, socklen);

    if (ls->wildcard) {
        ngx_crc32_update(&hash, (u_char *) local_sockaddr, local_socklen);
    }

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

        udp = (ngx_udp_connection_t *) node;

        c = udp->connection;

        rc = ngx_cmp_sockaddr(sockaddr, socklen,
                              c->sockaddr, c->socklen, 1);

        if (rc == 0 && ls->wildcard) {
            rc = ngx_cmp_sockaddr(local_sockaddr, local_socklen,
                                  c->local_sockaddr, c->local_socklen, 1);
        }

        if (rc == 0) {
            return c;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}
#endif
