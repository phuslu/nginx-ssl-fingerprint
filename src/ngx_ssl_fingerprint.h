#ifndef __NGX_SSL_FINGERPRINT__
#define __NGX_SSL_FINGERPRINT__

#include <ngx_core.h>
#include <ngx_http_v2.h>

#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))

int ngx_ssl_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *fingerprint);
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c, ngx_pool_t *pool, ngx_str_t *fingerprint);

#endif //__NGX_SSL_FINGERPRINT__
