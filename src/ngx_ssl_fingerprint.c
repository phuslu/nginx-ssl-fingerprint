#ifndef __NGX_SSL_FINGERPRINT__
#define __NGX_SSL_FINGERPRINT__

#include <ngx_core.h>

#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))

static inline
unsigned char *append_uint8(unsigned char* dst, unsigned char n)
{
    if (n > 99) {
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 3;
    } else if (n > 9) {
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 2;
    } else {
        *dst = n + '0';
        dst++;
    }

    return dst;
}

static inline
unsigned char *append_uint16(unsigned char* dst, unsigned short n)
{
    if (n > 9999) {
        *(dst+4) = n % 10 + '0';
        n /= 10;
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 5;
    } else if (n > 999) {
        *(dst+3) = n % 10 + '0';
        n /= 10;
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 4;
    } else if (n > 99) {
        *(dst+2) = n % 10 + '0';
        n /= 10;
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 3;
    } else if (n > 9) {
        *(dst+1) = n % 10 + '0';
        *dst = n / 10 + '0';
        dst += 2;
    } else {
        *dst = n + '0';
        dst++;
    }

    return dst;
}

int ngx_ssl_fingerprint(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *fingerprint)
{

    SSL *ssl;
    long len = 0;
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

    fingerprint->data = ngx_pnalloc(pool, 384);
    pstr = fingerprint->data;

    /* version */
    pstr = append_uint16(pstr, (unsigned short)SSL_version(ssl));

    /* ciphers */
    if ((len = SSL_ctrl(ssl, SSL_CTRL_GET_RAW_CIPHERLIST, 0, &pdata)) != 0) {
        *pstr++ = ',';
        pend = pdata + len;
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
    if (c->ssl->extensions.len) {
        pdata = c->ssl->extensions.data;
        pend = pdata + c->ssl->extensions.len;
        while (pdata < pend) {
            n = *(unsigned short*)pdata;
            if (!IS_GREASE_CODE(n)) {
                pstr = append_uint16(pstr, n);
                *pstr++ = '-';
            }
            pdata += 2;
        }
        *(pstr-1) = ',';
        // free memory
        ngx_pfree(c->pool, c->ssl->extensions.data);
    }

    /* curves */
    if ((len = SSL_ctrl(ssl, SSL_CTRL_GET_RAW_GROUPS, 0, &pdata)) != 0) {
        pend = pdata + len*2;
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
    if ((len = SSL_ctrl(ssl, SSL_CTRL_GET_EC_POINT_FORMATS, 0, &pdata)) != 0) {
        pend = pdata + len;
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
