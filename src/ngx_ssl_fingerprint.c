#ifndef __NGX_SSL_FINGERPRINT__
#define __NGX_SSL_FINGERPRINT__

#include <ngx_core.h>

int ngx_ssl_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *fingerprint)
{

    SSL *ssl;

    if (!c->ssl)
    {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked)
    {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl)
    {
        return NGX_DECLINED;
    }

    // version + ciphers & curves & curve formats + extensions.
    fingerprint->len = SSL_ctrl(c->ssl->connection, SSL_CTRL_GET_VERSION_CIPHERS_CURVES, 0, NULL) + 1 + c->ssl->extensions.len;

    // Alloc all needed memory.
    fingerprint->data = ngx_pnalloc(pool, fingerprint->len);
    // Get version & ciphers & curves & curve formats data.
    SSL_ctrl(c->ssl->connection, SSL_CTRL_GET_VERSION_CIPHERS_CURVES, 0, fingerprint->data);

    // Append extensions data and free its memory.
    if (c->ssl->extensions.len) {
        fingerprint->data[fingerprint->len - c->ssl->extensions.len - 1] = (unsigned char)c->ssl->extensions.len/2;
        memcpy(fingerprint->data + fingerprint->len - c->ssl->extensions.len, c->ssl->extensions.data, c->ssl->extensions.len);
        ngx_pfree(c->pool, c->ssl->extensions.data);
    } else {
        fingerprint->data[fingerprint->len-1] = 0;
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "clien hello version: [%d]\n", *(unsigned short*)fingerprint->data);

    ngx_log_error(NGX_LOG_ERR, c->log, 0, "clien hello fingerprint: [%d]\n", fingerprint->len);

    return NGX_OK;
}

#endif //__NGX_SSL_FINGERPRINT__
