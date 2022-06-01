#ifndef __NGX_SSL_FINGERPRINT__
#define __NGX_SSL_FINGERPRINT__

#include <ngx_core.h>

#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))

static inline
unsigned char *append_uint8(unsigned char* dst, unsigned char n)
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
unsigned char *append_uint16(unsigned char* dst, unsigned short n)
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

int ngx_ssl_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *fingerprint)
{

    SSL *ssl;
    unsigned char *pstr = NULL, *pdata = NULL, *pend = NULL;
    unsigned short n = 0;

    if (!c->ssl) {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked) {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl) {
        return NGX_DECLINED;
    }


    n = 32 + c->ssl->fp_ciphers.len * 6 + c->ssl->fp_extensions.len * 6 + c->ssl->fp_groups.len * 6 + c->ssl->fp_points.len * 4;
    fingerprint->data = ngx_pnalloc(pool, n);
    pstr = fingerprint->data;

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "ssl fingerprint alloc bytes: [%d]\n", n);
#endif

    /* version */
    pstr = append_uint16(pstr, (unsigned short)SSL_client_version(ssl));

    /* ciphers */
    if (c->ssl->fp_ciphers.len) {
        *pstr++ = ',';
        pdata = c->ssl->fp_ciphers.data;
        pend = pdata + c->ssl->fp_ciphers.len;
        while (pdata < pend) {
            n = ((unsigned short)(*pdata)<<8) + *(pdata+1);
            if (!IS_GREASE_CODE(n)) {
                pstr = append_uint16(pstr, n);
                *pstr++ = '-';
            }
            pdata += 2;
        }
        *(pstr-1) = ',';
    }

    /* extensions */
    if (c->ssl->fp_extensions.len) {
        pdata = c->ssl->fp_extensions.data;
        pend = pdata + c->ssl->fp_extensions.len*2;
        while (pdata < pend) {
            n = *(unsigned short*)pdata;
            if (!IS_GREASE_CODE(n)) {
                pstr = append_uint16(pstr, n);
                *pstr++ = '-';
            }
            pdata += 2;
        }
        *(pstr-1) = ',';
    }

    /* curves */
    if (c->ssl->fp_groups.len) {
        pdata = c->ssl->fp_groups.data;
        pend = pdata + c->ssl->fp_groups.len*2;
        while (pdata < pend) {
            n = *(unsigned short*)pdata;
            if (!IS_GREASE_CODE(n)) {
                pstr = append_uint16(pstr, n);
                *pstr++ = '-';
            }
            pdata += 2;
        }
        *(pstr-1) = ',';
    }

    /* formats */
    if (c->ssl->fp_points.len) {
        pdata = c->ssl->fp_points.data;
        pend = pdata + c->ssl->fp_points.len;
        while (pdata < pend) {
            pstr = append_uint8(pstr, *pdata);
            *pstr++ = '-';
            pdata++;
        }
    }

    /* null terminator */
    *--pstr = 0;

    fingerprint->len = pstr - fingerprint->data;

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "ssl fingerprint: [%V]\n", fingerprint);
#endif

    return NGX_OK;
}

#endif //__NGX_SSL_FINGERPRINT__
