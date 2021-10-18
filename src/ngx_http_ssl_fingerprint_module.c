#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_md5.h>

#include "ngx_ssl_fingerprint.h"

static ngx_int_t ngx_http_ssl_fingerprint_init(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_ssl_fingerprint_module_ctx = {
    NULL,                  /* preconfiguration */
    ngx_http_ssl_fingerprint_init, /* postconfiguration */
    NULL,                  /* create main configuration */
    NULL,                  /* init main configuration */
    NULL,                  /* create server configuration */
    NULL,                  /* merge server configuration */
    NULL,                  /* create location configuration */
    NULL                   /* merge location configuration */
};

ngx_module_t ngx_http_ssl_fingerprint_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_fingerprint_module_ctx, /* module context */
    NULL,                         /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING};


static ngx_int_t
ngx_http_ssl_fingerprint(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t fingerprint = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint(r->connection, r->pool, &fingerprint) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    v->data = fingerprint.data;
    v->len = fingerprint.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_http_variable_t ngx_http_ssl_fingerprint_variables_list[] = {
    {ngx_string("http_ssl_ja3"),
     NULL,
     ngx_http_ssl_fingerprint,
     0, 0, 0},
};

static ngx_int_t
ngx_http_ssl_fingerprint_init(ngx_conf_t *cf)
{

    ngx_http_variable_t *v;
    size_t l = 0;
    size_t vars_len;

    vars_len = (sizeof(ngx_http_ssl_fingerprint_variables_list) /
                sizeof(ngx_http_ssl_fingerprint_variables_list[0]));

    /* Register variables */
    for (l = 0; l < vars_len; ++l)
    {
        v = ngx_http_add_variable(cf,
                                  &ngx_http_ssl_fingerprint_variables_list[l].name,
                                  ngx_http_ssl_fingerprint_variables_list[l].flags);
        if (v == NULL)
        {
            continue;
        }
        *v = ngx_http_ssl_fingerprint_variables_list[l];
    }

    return NGX_OK;
}
