#ifndef __NGX_SSL_FINGERPRINT__
#define __NGX_SSL_FINGERPRINT__

int ngx_ssl_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *fingerprint);

#endif //__NGX_SSL_FINGERPRINT__
