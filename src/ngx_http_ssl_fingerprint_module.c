#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_http_v2.h>

static inline
unsigned char *append_uint8(unsigned char* dst, uint8_t n)
{
    if (n < 10) {
        *dst = n + '0';
        dst++;
    } else if (n < 100) {
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 2;
    } else {
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 3;
    }

    return dst;
}

static inline
unsigned char *append_uint16(unsigned char* dst, uint16_t n)
{
    if (n < 10) {
        *dst = n + '0';
        dst++;
    } else if (n < 100) {
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 3;
    }  else if (n < 10000) {
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 4;
    } else {
        *(dst+4) = n % 10 + '0';
        n /= 10;
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 5;
    }

    return dst;
}

static inline
unsigned char *append_uint32(unsigned char* dst, uint32_t n)
{
    if (n < 10) {
        *dst = n + '0';
        dst++;
    } else if (n < 100) {
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 3;
    } else if (n < 10000) {
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 4;
    } else if (n < 100000) {
        *(dst+4) = n % 10 + '0';
        n /= 10;
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 5;
    } else if (n < 1000000) {
        *(dst+5) = n % 10 + '0';
        n /= 10;
        *(dst+4) = n % 10 + '0';
        n /= 10;
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 6;
    } else if (n < 10000000) {
        *(dst+6) = n % 10 + '0';
        n /= 10;
        *(dst+5) = n % 10 + '0';
        n /= 10;
        *(dst+4) = n % 10 + '0';
        n /= 10;
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 7;
    } else if (n < 100000000) {
        *(dst+7) = n % 10 + '0';
        n /= 10;
        *(dst+6) = n % 10 + '0';
        n /= 10;
        *(dst+5) = n % 10 + '0';
        n /= 10;
        *(dst+4) = n % 10 + '0';
        n /= 10;
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 8;
    } else if (n < 1000000000) {
        *(dst+8) = n % 10 + '0';
        n /= 10;
        *(dst+7) = n % 10 + '0';
        n /= 10;
        *(dst+6) = n % 10 + '0';
        n /= 10;
        *(dst+5) = n % 10 + '0';
        n /= 10;
        *(dst+4) = n % 10 + '0';
        n /= 10;
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 9;
    } else {
        *(dst+9) = n % 10 + '0';
        n /= 10;
        *(dst+8) = n % 10 + '0';
        n /= 10;
        *(dst+7) = n % 10 + '0';
        n /= 10;
        *(dst+6) = n % 10 + '0';
        n /= 10;
        *(dst+5) = n % 10 + '0';
        n /= 10;
        *(dst+4) = n % 10 + '0';
        n /= 10;
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 10;
    }

    return dst;
}

int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c, ngx_pool_t *pool, ngx_str_t *fingerprint)
{
    unsigned char *pstr = NULL;
    unsigned short n = 0;
    size_t i;

    if (!h2c) {
        return NGX_DECLINED;
    }

    n = 4 + h2c->fp_settings.len * 3 + 10 + h2c->fp_priorities.len * 2 + h2c->fp_pseudoheaders.len * 2;
    fingerprint->data = ngx_pnalloc(pool, n);
    pstr = fingerprint->data;

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "http2 fingerprint alloc bytes: [%d]\n", n);
#endif

    /* setting */
    for (i = 0; i < h2c->fp_settings.len; i+=5) {
        pstr = append_uint8(pstr, h2c->fp_settings.data[i]);
        *pstr++ = ':';
        pstr = append_uint32(pstr, *(uint32_t*)(h2c->fp_settings.data+i+1));
        *pstr++ = ';';
    }
    *(pstr-1) = '|';

    /* windows update */
    pstr = append_uint32(pstr, h2c->fp_windowupdate);
    *pstr++ = '|';

    /* priorities */
    for (i = 0; i < h2c->fp_priorities.len; i+=4) {
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+1]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+2]);
        *pstr++ = ':';
        pstr = append_uint16(pstr, (uint16_t)h2c->fp_priorities.data[i+3]+1);
        *pstr++ = ',';
    }
    *(pstr-1) = '|';

    /* fp_pseudoheaders */
    for (i = 0; i < h2c->fp_pseudoheaders.len; i++) {
        *pstr++ = h2c->fp_pseudoheaders.data[i];
        *pstr++ = ',';
    }

    /* null terminator */
    *--pstr = 0;

    fingerprint->len = pstr - fingerprint->data;

    h2c->fp_fingerprinted = 1;

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "http2 fingerprint: [%V]\n", fingerprint);
#endif

    return NGX_OK;
}

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
ngx_http_ssl_greased(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (r->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    v->len = 1;
    v->data = (u_char*)(r->connection->ssl->fp_tls_greased ? "1" : "0");

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_fingerprint(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (r->connection->ssl == NULL)
    {
        return NGX_OK;
    }

    if (r->connection->ssl->fp_ja3_str.data == NULL) {
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja3_str.data;
    v->len = r->connection->ssl->fp_ja3_str.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_http2_fingerprint(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t fingerprint = ngx_null_string;

    if (r->stream == NULL)
    {
        return NGX_OK;
    }

    if (ngx_http2_fingerprint(r->connection, r->stream->connection, r->pool, &fingerprint) == NGX_DECLINED)
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
    {ngx_string("http_ssl_greased"),
     NULL,
     ngx_http_ssl_greased,
     0, 0, 0},
    {ngx_string("http_ssl_ja3"),
     NULL,
     ngx_http_ssl_fingerprint,
     0, 0, 0},
    {ngx_string("http2_fingerprint"),
     NULL,
     ngx_http_http2_fingerprint,
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
