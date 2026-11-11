
/*
 * Please make sure that you have been incuded --with-streams_ssl_moduke
 * before --add-module Else this module won't be compiled
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_md5.h>

extern int ngx_ssl_ja3(ngx_connection_t *c);
extern int ngx_ssl_ja3_hash(ngx_connection_t *c);
extern int ngx_ssl_ja4(ngx_connection_t *c);

static ngx_int_t ngx_stream_ssl_fingerprint_preread_init(ngx_conf_t *cf);
static void *ngx_stream_ssl_fingerprint_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_ssl_fingerprint_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

typedef struct {
    ngx_flag_t  ja3;
    ngx_flag_t  ja4;
} ngx_stream_ssl_fingerprint_conf_t;

static ngx_command_t  ngx_stream_ssl_fingerprint_commands[] = {
    { ngx_string("ngx_ja3"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ssl_fingerprint_conf_t, ja3),
      NULL },

    { ngx_string("ngx_ja4"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ssl_fingerprint_conf_t, ja4),
      NULL },

      ngx_null_command
};

static ngx_stream_module_t  ngx_stream_ssl_fingerprint_preread_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_stream_ssl_fingerprint_preread_init,          /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    ngx_stream_ssl_fingerprint_create_srv_conf,       /* create server configuration */
    ngx_stream_ssl_fingerprint_merge_srv_conf         /* merge server configuration */
};

ngx_module_t  ngx_stream_ssl_fingerprint_preread_module = {
    NGX_MODULE_V1,
    &ngx_stream_ssl_fingerprint_preread_module_ctx,      /* module context */
    ngx_stream_ssl_fingerprint_commands,                /* module directives */
    NGX_STREAM_MODULE,                                   /* module type */
    NULL,                                                /* init master */
    NULL,                                                /* init module */
    NULL,                                                /* init process */
    NULL,                                                /* init thread */
    NULL,                                                /* exit thread */
    NULL,                                                /* exit process */
    NULL,                                                /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_stream_ssl_greased(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_fingerprint_conf_t  *scf;

    v->not_found = 1;

    scf = ngx_stream_get_module_srv_conf(s,
        ngx_stream_ssl_fingerprint_preread_module);
    if (scf->ja3 == 0) {
        return NGX_OK;
    }

    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(s->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->len = 1;
    v->data = (u_char*)(s->connection->ssl->fp_tls_greased ? "1" : "0");

    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_ja3(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_fingerprint_conf_t  *scf;

    v->not_found = 1;

    scf = ngx_stream_get_module_srv_conf(s,
        ngx_stream_ssl_fingerprint_preread_module);
    if (scf->ja3 == 0) {
        return NGX_OK;
    }

    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(s->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = s->connection->ssl->fp_ja3_str.data;
    v->len = s->connection->ssl->fp_ja3_str.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_ja3_hash(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_fingerprint_conf_t  *scf;

    v->not_found = 1;

    scf = ngx_stream_get_module_srv_conf(s,
        ngx_stream_ssl_fingerprint_preread_module);
    if (scf->ja3 == 0) {
        return NGX_OK;
    }

    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja3_hash(s->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = s->connection->ssl->fp_ja3_hash.data;
    v->len = s->connection->ssl->fp_ja3_hash.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_ssl_ja4(ngx_stream_session_t *s,
                 ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_ssl_fingerprint_conf_t  *scf;

    v->not_found = 1;

    scf = ngx_stream_get_module_srv_conf(s,
        ngx_stream_ssl_fingerprint_preread_module);
    if (scf->ja4 == 0) {
        return NGX_OK;
    }

    if (s->connection == NULL)
    {
        return NGX_OK;
    }

    if (s->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4(s->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = s->connection->ssl->fp_ja4_str.data;
    v->len = s->connection->ssl->fp_ja4_str.len;
    v->valid = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_stream_variable_t  ngx_stream_ssl_fingerprint_variables_list[] = {

    {   ngx_string("stream_ssl_greased"),
        NULL,
        ngx_stream_ssl_greased,
        0, 0, 0
    },

    {   ngx_string("stream_ssl_ja3"),
        NULL,
        ngx_stream_ssl_ja3,
        0, 0, 0
    },

    {   ngx_string("stream_ssl_ja3_hash"),
        NULL,
        ngx_stream_ssl_ja3_hash,
        0, 0, 0
    },

    {   ngx_string("stream_ssl_ja4"),
        NULL,
        ngx_stream_ssl_ja4,
        0, 0, 0
    },

};

static ngx_int_t
ngx_stream_ssl_fingerprint_preread_init(ngx_conf_t *cf)
{
    ngx_stream_variable_t          *v;
    size_t                        l = 0;
    size_t                        vars_len;

    vars_len = (sizeof(ngx_stream_ssl_fingerprint_variables_list) /
            sizeof(ngx_stream_ssl_fingerprint_variables_list[0]));

    /* Register variables */
    for (l = 0; l < vars_len ; ++l) {
        v = ngx_stream_add_variable(cf,
                &ngx_stream_ssl_fingerprint_variables_list[l].name,
                ngx_stream_ssl_fingerprint_variables_list[l].flags);
        if (v == NULL) {
            continue;
        }
        *v = ngx_stream_ssl_fingerprint_variables_list[l];
    }

    return NGX_OK;
}


static void *
ngx_stream_ssl_fingerprint_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_ssl_fingerprint_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_ssl_fingerprint_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->ja3 = NGX_CONF_UNSET;
    conf->ja4 = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_stream_ssl_fingerprint_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_stream_ssl_fingerprint_conf_t *prev = parent;
    ngx_stream_ssl_fingerprint_conf_t *conf = child;

    ngx_conf_merge_value(conf->ja3, prev->ja3, 1);
    ngx_conf_merge_value(conf->ja4, prev->ja4, 1);

    return NGX_CONF_OK;
}
