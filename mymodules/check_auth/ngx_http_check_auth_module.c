#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_core_module.h"

#define UNUSED(x) (void)(x)

typedef struct
{
	ngx_int_t check_auth;
} ngx_http_check_auth_loc_conf_t;

static ngx_int_t ngx_http_check_auth_init(ngx_conf_t *cf);
static char *ngx_set_check_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_check_auth_create_loc_conf(ngx_conf_t *cf);

static ngx_command_t ngx_http_check_auth_commands[] = {
	{
		ngx_string("check_auth"),
		NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_set_check_auth,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_check_auth_loc_conf_t, check_auth),
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_check_auth_module_ctx = {
    NULL,                     /* preconfiguration */
    ngx_http_check_auth_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_check_auth_create_loc_conf, /* create location configuration */
    NULL  /* merge location configuration */
};


ngx_module_t ngx_http_check_auth_module = {
        NGX_MODULE_V1,
        &ngx_http_check_auth_module_ctx,    /* module context */
        ngx_http_check_auth_commands,       /* module directives */
        NGX_HTTP_MODULE,               /* module type */
        NULL,                          /* init master */
        NULL,                          /* init module */
        NULL,                          /* init process */
        NULL,                          /* init thread */
        NULL,                          /* exit thread */
        NULL,                          /* exit process */
        NULL,                          /* exit master */
        NGX_MODULE_V1_PADDING
};

static void *ngx_http_check_auth_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_check_auth_loc_conf_t *local_conf = NULL;

	local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_check_auth_loc_conf_t));
	if (local_conf == NULL)
	{
		return NULL;
	}

	local_conf->check_auth = NGX_CONF_UNSET;

	return local_conf;
}

static char *ngx_set_check_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	// ngx_http_check_auth_loc_conf_t *local_conf;

	// local_conf = conf;

	char *rv = NULL;

	rv = ngx_conf_set_flag_slot(cf, cmd, conf);

	return rv;
}

static ngx_int_t ngx_http_check_auth_handler(ngx_http_request_t *r)
{
	ngx_http_check_auth_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_check_auth_module);
	if (conf->check_auth != 1)
		return NGX_ERROR;
	// ngx_str_t                  var = ngx_string("uri");
	// ngx_uint_t                 key = ngx_hash_key(var.data, var.len);
	// ngx_http_variable_value_t *vv  = ngx_http_get_variable(r, &var, key);
	// UNUSED(vv);
	if (ngx_strstr(r->args_start, "auth="))
		return NGX_OK;  // ngx_http_output_filter(r, &out);
	return NGX_ERROR;
}

//static void *ngx_http_hello_create_loc_conf(ngx_conf_t *cf)
//{
//        ngx_http_hello_loc_conf_t* local_conf = NULL;
//        local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_loc_conf_t));
//        if (local_conf == NULL)
//        {
//                return NULL;
//        }
// 
//        ngx_str_null(&local_conf->hello_string);
//        local_conf->hello_counter = NGX_CONF_UNSET;
// 
//        return local_conf;
//}

/*
static char *ngx_http_hello_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
        ngx_http_hello_loc_conf_t* prev = parent;
        ngx_http_hello_loc_conf_t* conf = child;

        ngx_conf_merge_str_value(conf->hello_string, prev->hello_string, ngx_hello_default_string);
        ngx_conf_merge_value(conf->hello_counter, prev->hello_counter, 0);

        return NGX_CONF_OK;
}*/

static ngx_int_t ngx_http_check_auth_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt       *h;
	ngx_http_core_main_conf_t *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	// ngx_http_check_auth_loc_conf_t *check_auth_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_check_auth_module);

	// if (check_auth_conf->check_auth == 1)
	{
		h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
		if (h == NULL)
		{
			return NGX_ERROR;
		}

		*h = ngx_http_check_auth_handler;
	}

	return NGX_OK;
}
