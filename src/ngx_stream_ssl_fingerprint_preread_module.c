#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_md5.h>

extern int ngx_ssl_ja3(ngx_connection_t *c);

static ngx_int_t ngx_stream_ssl_fingerprint_preread_init(ngx_conf_t *cf);

static ngx_stream_module_t  ngx_stream_ssl_fingerprint_preread_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_stream_ssl_fingerprint_preread_init,          /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL                                      /* merge server configuration */
};

ngx_module_t  ngx_stream_ssl_fingerprint_preread_module = {
    NGX_MODULE_V1,
    &ngx_stream_ssl_fingerprint_preread_module_ctx,      /* module context */
    NULL,                                        /* module directives */
    NGX_STREAM_MODULE,                           /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    NULL,                                        /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_stream_ssl_greased(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(s->connection) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    v->len = 1;
    v->data = (u_char*)(s->connection->ssl->fp_tls_greased ? "1" : "0");

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_fingerprint(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(s->connection) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    v->data = s->connection->ssl->fp_ja3_str.data;
    v->len = s->connection->ssl->fp_ja3_str.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_fingerprint_hash(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_md5_t               ctx;
    u_char                  hash_buf[16];


    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(s->connection) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    v->data = ngx_pcalloc(s->connection->pool, 32);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, s->connection->ssl->fp_ja3_str.data, s->connection->ssl->fp_ja3_str.len);
    ngx_md5_final(hash_buf, &ctx);
    ngx_hex_dump(v->data, hash_buf, 16);

    v->len = 32;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_stream_variable_t  ngx_stream_ssl_ja3_variables_list[] = {

    {   ngx_string("stream_ssl_greased"),
        NULL,
        ngx_stream_ssl_greased,
        0, 0, 0
    },

    {   ngx_string("stream_ssl_ja3"),
        NULL,
        ngx_stream_ssl_fingerprint,
        0, 0, 0
    },

    {   ngx_string("stream_ssl_ja3_hash"),
        NULL,
        ngx_stream_ssl_fingerprint_hash,
        0, 0, 0
    },

};

static ngx_int_t
ngx_stream_ssl_fingerprint_preread_init(ngx_conf_t *cf)
{
    ngx_stream_variable_t          *v;
    size_t                        l = 0;
    size_t                        vars_len;

    vars_len = (sizeof(ngx_stream_ssl_ja3_variables_list) /
            sizeof(ngx_stream_ssl_ja3_variables_list[0]));

    /* Register variables */
    for (l = 0; l < vars_len ; ++l) {
        v = ngx_stream_add_variable(cf,
                &ngx_stream_ssl_ja3_variables_list[l].name,
                ngx_stream_ssl_ja3_variables_list[l].flags);
        if (v == NULL) {
            continue;
        }
        *v = ngx_stream_ssl_ja3_variables_list[l];
    }

    return NGX_OK;
}
