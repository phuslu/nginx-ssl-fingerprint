
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <nginx_ssl_fingerprint.h>

static ngx_int_t ngx_http_ssl_fingerprint_init(ngx_conf_t *cf);
static void *ngx_http_ssl_fingerprint_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_fingerprint_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_ssl_greased(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja3(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja3_hash(ngx_http_request_t *r,
                             ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja4(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_http2_fingerprint(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);

typedef struct {
    ngx_flag_t  ja3;
    ngx_flag_t  ja4;
} ngx_http_ssl_fingerprint_conf_t;

static ngx_command_t  ngx_http_ssl_fingerprint_commands[] = {
    { ngx_string("ngx_ja3"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssl_fingerprint_conf_t, ja3),
      NULL },

    { ngx_string("ngx_ja4"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ssl_fingerprint_conf_t, ja4),
      NULL },

      ngx_null_command
};

static ngx_http_module_t ngx_http_ssl_fingerprint_module_ctx = {
    ngx_http_ssl_fingerprint_init,  /* preconfiguration */
    NULL,                           /* postconfiguration */
    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */
    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */
    ngx_http_ssl_fingerprint_create_loc_conf,   /* create location configuration */
    ngx_http_ssl_fingerprint_merge_loc_conf     /* merge location configuration */
};

ngx_module_t ngx_http_ssl_fingerprint_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_fingerprint_module_ctx, /* module context */
    ngx_http_ssl_fingerprint_commands,    /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_variable_t ngx_http_ssl_fingerprint_variables_list[] = {
    {ngx_string("http_ssl_greased"), NULL, ngx_http_ssl_greased,
     0, 0, 0},
    {ngx_string("http_ssl_ja3"), NULL, ngx_http_ssl_ja3,
     0, 0, 0},
    {ngx_string("http_ssl_ja3_hash"), NULL, ngx_http_ssl_ja3_hash,
     0, 0, 0},
    {ngx_string("http_ssl_ja4"), NULL, ngx_http_ssl_ja4,
     0, 0, 0},
    {ngx_string("http2_fingerprint"), NULL, ngx_http_http2_fingerprint,
     0, 0, 0},
    ngx_http_null_variable
};

static ngx_int_t
ngx_http_ssl_greased(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ssl_fingerprint_conf_t  *lcf;

    /* For access.log's map $http2_VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_ssl_fingerprint_module);
    if (lcf->ja3 == 0) {
        return NGX_OK;
    }

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(r->connection) != NGX_OK) {
        return NGX_OK;
    }

    v->len = 1;
    v->data = (u_char*) (r->connection->ssl->fp_tls_greased ? "1" : "0");
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja3(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ssl_fingerprint_conf_t  *lcf;

    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_ssl_fingerprint_module);
    if (lcf->ja3 == 0) {
        return NGX_OK;
    }

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(r->connection) != NGX_OK) {
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja3_str.data;
    v->len = r->connection->ssl->fp_ja3_str.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja3_hash(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ssl_fingerprint_conf_t  *lcf;

    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_ssl_fingerprint_module);
    if (lcf->ja3 == 0) {
        return NGX_OK;
    }

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja3_hash(r->connection) != NGX_OK) {
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja3_hash.data;
    v->len = r->connection->ssl->fp_ja3_hash.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja4(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ssl_fingerprint_conf_t  *lcf;

    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_ssl_fingerprint_module);
    if (lcf->ja4 == 0) {
        return NGX_OK;
    }

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4(r->connection) != NGX_OK) {
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja4_str.data;
    v->len = r->connection->ssl->fp_ja4_str.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_http2_fingerprint(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  fp;

    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    if (r->stream == NULL) {
        return NGX_OK;
    }

    if (ngx_http2_fingerprint(r, &fp)
            != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = fp.data;
    v->len = fp.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static void *
ngx_http_ssl_fingerprint_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_fingerprint_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_fingerprint_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->ja3 = NGX_CONF_UNSET;
    conf->ja4 = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_ssl_fingerprint_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_ssl_fingerprint_conf_t *prev = parent;
    ngx_http_ssl_fingerprint_conf_t *conf = child;

    ngx_conf_merge_value(conf->ja3, prev->ja3, 1);
    ngx_conf_merge_value(conf->ja4, prev->ja4, 1);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ssl_fingerprint_init(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ssl_fingerprint_variables_list; v->name.len; v++) {

        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        /** NOTE: update it, if set_handler will be needed */
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

