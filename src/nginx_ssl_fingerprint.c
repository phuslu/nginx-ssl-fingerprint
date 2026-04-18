#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_http_v2.h>
#include <ngx_md5.h>
#include <openssl/sha.h>

#include <nginx_ssl_fingerprint.h>

#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))

static inline
unsigned char *append_uint8(unsigned char* dst, uint8_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    }

    return dst;
}

static inline
unsigned char *append_uint16(unsigned char* dst, uint16_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    }  else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;
    } else {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    }

    return dst;
}

static inline
unsigned char *append_uint32(unsigned char* dst, uint32_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    } else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;
    } else if (n < 100000) {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    } else if (n < 1000000) {
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 6;
    } else if (n < 10000000) {
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 7;
    } else if (n < 100000000) {
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 8;
    } else if (n < 1000000000) {
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 9;
    } else {
        dst[9] = n % 10 + '0';
        n /= 10;
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 10;
    }

    return dst;
}

/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_str is already set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja3(ngx_connection_t *c)
{
    u_char *ptr = NULL, *data = NULL;
    size_t num = 0, i;
    uint16_t n, greased = 0;

    data = c->ssl->fp_ja_data.data;
    if (data == NULL) {
        /**
         *  NOTE:
         *  If we can't set it in OpenSSL,
         *  then something defenetly something went wrong.
         *  Typical production configuration has log level set to error,
         *  this would help to debug this case, if it happened.
         */
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja3: fp_ja_data == NULL");
        return NGX_ERROR;
    }

    if (c->ssl->fp_ja3_str.data != NULL) {
        return NGX_OK;
    }

    c->ssl->fp_ja3_str.len = c->ssl->fp_ja_data.len * 4;
    c->ssl->fp_ja3_str.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_str.len);
    if (c->ssl->fp_ja3_str.data == NULL) {
        /** Else we break a data stream */
        c->ssl->fp_ja3_str.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3: alloc bytes: [%d]\n", c->ssl->fp_ja3_str.len);

    /* version */
    ptr = c->ssl->fp_ja3_str.data;
    ptr = append_uint16(ptr, *(uint16_t*)data);
    *ptr++ = ',';
    data += 2;

    /* ciphers */
    num = *(uint16_t*)data;
    for (i = 2; i <= num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            /* if (data[i] == 0x13) {
                c->ssl->fp_ja3_str.data[2] = '2'; // fixup tls1.3 version
            } */
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        } else if (greased == 0) {
            greased = n;
        }
    }
    *(ptr-1) = ',';
    data += 2 + num;

    /* extensions */
    num = *(uint16_t*)data;
    for (i = 2; i <= num; i += 2) {
        n = *(uint16_t*)(data+i);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        }
    }
    if (num != 0) {
        *(ptr-1) = ',';
        data += 2 + num;
    } else {
        *(ptr++) = ',';
    }


    /* groups */
    num = *(uint16_t*)data;
    for (i = 2; i + 1 < num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        }
    }
    if (num != 0) {
        *(ptr-1) = ',';
        data += num;
    } else {
        *(ptr++) = ',';
    }

    /* formats */
    num = *(uint8_t*)data;
    for (i = 1; i < num; i++) {
        ptr = append_uint16(ptr, (uint16_t)data[i]);
        *ptr++ = '-';
    }
    if (num != 0) {
        data += num;
        *(ptr-1) = ',';
        *ptr-- = 0;
    }

    /* end */
    c->ssl->fp_ja3_str.len = ptr - c->ssl->fp_ja3_str.data;

    /* greased */
    c->ssl->fp_tls_greased = greased;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3: ja3 str=[%V], len=[%d]", &c->ssl->fp_ja3_str, c->ssl->fp_ja3_str.len);

    return NGX_OK;
}

/**
 * Params:
 *      c and c->ssl should be valid pointers and tested before.
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_hash is alread set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja3_hash(ngx_connection_t *c)
{
    ngx_md5_t ctx;
    u_char hash_buf[16];

    if (c->ssl->fp_ja3_hash.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(c) != NGX_OK) {
        return NGX_ERROR;
    }

    c->ssl->fp_ja3_hash.len = 32;
    c->ssl->fp_ja3_hash.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_hash.len);
    if (c->ssl->fp_ja3_hash.data == NULL) {
        /** Else we can break a stream */
        c->ssl->fp_ja3_hash.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3_hash: alloc bytes: [%d]\n", c->ssl->fp_ja3_hash.len);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, c->ssl->fp_ja3_str.data, c->ssl->fp_ja3_str.len);
    ngx_md5_final(hash_buf, &ctx);
    ngx_hex_dump(c->ssl->fp_ja3_hash.data, hash_buf, 16);

    return NGX_OK;
}

/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4_str is already set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja4(ngx_connection_t *c)
{
    u_char        *ptr, *data, *end, *sigalgs_data;
    size_t         ciphers_len, exts_len, groups_len, formats_len,
                   sigalgs_len, alpn_len;
    size_t         cipher_count, exts_count, exts_count_total, sigalg_count;
    size_t         i, j;
    uint16_t       n, version_code, hash_buf[128];
    unsigned char  alpn[2] = { '0', '0' };
    unsigned char  cipher_hash[6] = { 0 }, exts_hash[6] = { 0 }, hash_part[5],
                   digest[SHA256_DIGEST_LENGTH];
    static const unsigned char  hex[] = "0123456789abcdef";
    ngx_flag_t    has_sni;
    SHA256_CTX    sha256;
    enum {
        ngx_ssl_ja4_max_fields = 128,
        ngx_ssl_ja4_str_max_len = 38,
        ngx_ssl_ja4_hex_hash_len = 12
    };

    data = c->ssl->fp_ja_data.data;
    if (data == NULL) {
        /**
         *  NOTE:
         *  If we can't set it in OpenSSL,
         *  then something defenetly something went wrong.
         *  Typical production configuration has log level set to error,
         *  this would help to debug this case, if it happened.
         */
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: fp_ja_data == NULL");
        return NGX_ERROR;
    }

    if (c->ssl->fp_ja4_str.data != NULL) {
        return NGX_OK;
    }

    end = data + c->ssl->fp_ja_data.len;

    if ((size_t) (end - data) < sizeof(uint16_t) * 6 + sizeof(uint8_t) + 3) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: fp_ja_data too short");
        return NGX_ERROR;
    }

    version_code = *(uint16_t *) data;
    data += sizeof(uint16_t);

    /* ciphers */
    ciphers_len = *(uint16_t *) data;
    data += sizeof(uint16_t);
    if (ciphers_len > (size_t) (end - data) || (ciphers_len & 1) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: invalid ciphers length");
        return NGX_ERROR;
    }

    cipher_count = 0;
    for (i = 0; i + 1 < ciphers_len; i += 2) {
        n = ((uint16_t) data[i] << 8) | (uint16_t) data[i + 1];
        if (!IS_GREASE_CODE(n)) {
            if (cipher_count >= ngx_ssl_ja4_max_fields) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                        "ngx_ssl_ja4: too many ciphers");
                return NGX_ERROR;
            }
            hash_buf[cipher_count++] = n;
        }
    }
    data += ciphers_len;

    if (cipher_count != 0) {
        for (i = 1; i < cipher_count; i++) {
            n = hash_buf[i];
            for (j = i; j > 0 && hash_buf[j - 1] > n; j--) {
                hash_buf[j] = hash_buf[j - 1];
            }
            hash_buf[j] = n;
        }

        if (SHA256_Init(&sha256) != 1) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: SHA256_Init failed");
            return NGX_ERROR;
        }

        for (i = 0; i < cipher_count; i++) {
            hash_part[0] = hex[(hash_buf[i] >> 12) & 0xf];
            hash_part[1] = hex[(hash_buf[i] >> 8) & 0xf];
            hash_part[2] = hex[(hash_buf[i] >> 4) & 0xf];
            hash_part[3] = hex[hash_buf[i] & 0xf];
            hash_part[4] = ',';
            if (SHA256_Update(&sha256, hash_part,
                              (i + 1 == cipher_count) ? 4 : 5) != 1)
            {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                        "ngx_ssl_ja4: SHA256_Update failed");
                return NGX_ERROR;
            }
        }

        if (SHA256_Final(digest, &sha256) != 1) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: SHA256_Final failed");
            return NGX_ERROR;
        }
        ngx_memcpy(cipher_hash, digest, sizeof(cipher_hash));
    }

    /* extensions */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing extensions block");
        return NGX_ERROR;
    }

    exts_len = *(uint16_t *) data;
    data += sizeof(uint16_t);
    if (exts_len > (size_t) (end - data) || (exts_len & 1) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: invalid extensions length");
        return NGX_ERROR;
    }

    exts_count = 0;
    exts_count_total = 0;
    has_sni = 0;
    for (i = 0; i + 1 < exts_len; i += 2) {
        n = *(uint16_t *) (data + i);

        if (IS_GREASE_CODE(n)) {
            continue;
        }

        exts_count_total++;

        if (n == 0x0000) {
            has_sni = 1;
            continue;
        }

        if (n == 0x0010) {
            continue;
        }

        if (exts_count >= ngx_ssl_ja4_max_fields) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: too many extensions");
            return NGX_ERROR;
        }

        hash_buf[exts_count++] = n;
    }
    data += exts_len;

    /* groups */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing groups block");
        return NGX_ERROR;
    }

    groups_len = *(uint16_t *) data;
    if (groups_len == 0) {
        data += sizeof(uint16_t);
    } else {
        if (groups_len < sizeof(uint16_t)
            || groups_len > (size_t) (end - data))
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: invalid groups length");
            return NGX_ERROR;
        }
        data += groups_len;
    }

    /* formats */
    if ((size_t) (end - data) < sizeof(uint8_t)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing formats block");
        return NGX_ERROR;
    }

    formats_len = data[0];
    if (formats_len == 0) {
        data += sizeof(uint8_t);
    } else {
        if (formats_len > (size_t) (end - data)) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: invalid formats length");
            return NGX_ERROR;
        }
        data += formats_len;
    }

    /* supported version */
    if ((size_t) (end - data) < sizeof(uint16_t) * 2) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing ja4 metadata block");
        return NGX_ERROR;
    }

    if (*(uint16_t *) data != 0) {
        version_code = *(uint16_t *) data;
    }
    data += sizeof(uint16_t);

    /* signature algorithms */
    sigalgs_data = data;
    sigalgs_len = *(uint16_t *) data;
    if (sigalgs_len == 0) {
        data += sizeof(uint16_t);
    } else {
        if (sigalgs_len < sizeof(uint16_t)
            || sigalgs_len > (size_t) (end - data)
            || (sigalgs_len & 1) != 0)
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: invalid signature algorithms length");
            return NGX_ERROR;
        }

        data += sigalgs_len;
    }

    /* alpn 2 digits */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing alpn block");
        return NGX_ERROR;
    }

    alpn_len = *(uint16_t *) data;
    if (alpn_len == 0) {
        data += sizeof(uint16_t);
    } else {
        if (alpn_len < sizeof(uint16_t) + 2
            || alpn_len > (size_t) (end - data))
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: invalid alpn length");
            return NGX_ERROR;
        }

        n = data[2];
        if (n == 0 || n > alpn_len - 3) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: invalid alpn length");
            return NGX_ERROR;
        }
        alpn[0] = data[3];
        alpn[1] = data[n + 2];
        data += alpn_len;
    }

    /* extensions and sigalgs digest */
    if (exts_count != 0) {
        for (i = 1; i < exts_count; i++) {
            n = hash_buf[i];
            for (j = i; j > 0 && hash_buf[j - 1] > n; j--) {
                hash_buf[j] = hash_buf[j - 1];
            }
            hash_buf[j] = n;
        }

        if (SHA256_Init(&sha256) != 1) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: SHA256_Init failed");
            return NGX_ERROR;
        }

        sigalg_count = 0;
        for (i = sizeof(uint16_t); i + 1 < sigalgs_len; i += 2) {
            n = ((uint16_t) sigalgs_data[i] << 8)
                | (uint16_t) sigalgs_data[i + 1];
            if (!IS_GREASE_CODE(n)) {
                if (sigalg_count >= ngx_ssl_ja4_max_fields) {
                    ngx_log_error(NGX_LOG_WARN, c->log, 0,
                            "ngx_ssl_ja4: too many signature algorithms");
                    return NGX_ERROR;
                }
                sigalg_count++;
            }
        }

        for (i = 0; i < exts_count; i++) {
            hash_part[0] = hex[(hash_buf[i] >> 12) & 0xf];
            hash_part[1] = hex[(hash_buf[i] >> 8) & 0xf];
            hash_part[2] = hex[(hash_buf[i] >> 4) & 0xf];
            hash_part[3] = hex[hash_buf[i] & 0xf];
            hash_part[4] = (i + 1 == exts_count && sigalg_count != 0) ? '_' : ',';
            if (SHA256_Update(&sha256, hash_part,
                              (i + 1 == exts_count && sigalg_count == 0) ? 4 : 5) != 1)
            {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                        "ngx_ssl_ja4: SHA256_Update failed");
                return NGX_ERROR;
            }
        }

        if (sigalg_count != 0) {
            j = 0;
            for (i = sizeof(uint16_t); i + 1 < sigalgs_len; i += 2) {
                n = ((uint16_t) sigalgs_data[i] << 8)
                    | (uint16_t) sigalgs_data[i + 1];
                if (!IS_GREASE_CODE(n)) {
                    hash_buf[j++] = n;
                }
            }

            for (i = 1; i < sigalg_count; i++) {
                n = hash_buf[i];
                for (j = i; j > 0 && hash_buf[j - 1] > n; j--) {
                    hash_buf[j] = hash_buf[j - 1];
                }
                hash_buf[j] = n;
            }

            for (i = 0; i < sigalg_count; i++) {
                hash_part[0] = hex[(hash_buf[i] >> 12) & 0xf];
                hash_part[1] = hex[(hash_buf[i] >> 8) & 0xf];
                hash_part[2] = hex[(hash_buf[i] >> 4) & 0xf];
                hash_part[3] = hex[hash_buf[i] & 0xf];
                hash_part[4] = ',';
                if (SHA256_Update(&sha256, hash_part,
                                  (i + 1 == sigalg_count) ? 4 : 5) != 1)
                {
                    ngx_log_error(NGX_LOG_WARN, c->log, 0,
                            "ngx_ssl_ja4: SHA256_Update failed");
                    return NGX_ERROR;
                }
            }
        }

        if (SHA256_Final(digest, &sha256) != 1) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: SHA256_Final failed");
            return NGX_ERROR;
        }
        ngx_memcpy(exts_hash, digest, sizeof(exts_hash));
    }

    /* ja4 str */
    c->ssl->fp_ja4_str.len = ngx_ssl_ja4_str_max_len;
    c->ssl->fp_ja4_str.data = ngx_pnalloc(c->pool, c->ssl->fp_ja4_str.len);
    if (c->ssl->fp_ja4_str.data == NULL) {
        /** Else we break a data stream */
        c->ssl->fp_ja4_str.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja4: alloc bytes: [%d]\n", c->ssl->fp_ja4_str.len);

    ptr = c->ssl->fp_ja4_str.data;
#if (NGX_QUIC || NGX_COMPAT)
    *ptr++ = c->quic ? 'q' : 't';
#else
    *ptr++ = 't';
#endif
    switch (version_code) {
    case TLS1_3_VERSION:
        *ptr++ = '1';
        *ptr++ = '3';
        break;
    case TLS1_2_VERSION:
        *ptr++ = '1';
        *ptr++ = '2';
        break;
    case TLS1_1_VERSION:
        *ptr++ = '1';
        *ptr++ = '1';
        break;
    case TLS1_VERSION:
        *ptr++ = '1';
        *ptr++ = '0';
        break;
    case SSL3_VERSION:
        *ptr++ = 's';
        *ptr++ = '3';
        break;
    default:
        *ptr++ = '0';
        *ptr++ = '0';
        break;
    }
    *ptr++ = has_sni ? 'd' : 'i';
    if (cipher_count < 10) {
        *ptr++ = '0';
    }
    ptr = append_uint8(ptr, (uint8_t) cipher_count);
    if (exts_count_total < 10) {
        *ptr++ = '0';
    }
    ptr = append_uint8(ptr, (uint8_t) exts_count_total);
    if (isalnum(alpn[0]) && isalnum(alpn[1])) {
        *ptr++ = alpn[0];
        *ptr++ = alpn[1];
    } else {
        *ptr++ = hex[alpn[0] >> 4];
        *ptr++ = hex[alpn[1] & 0xf];
    }
    *ptr++ = '_';
    ptr = ngx_hex_dump(ptr, cipher_hash, ngx_ssl_ja4_hex_hash_len / 2);

    *ptr++ = '_';
    ptr = ngx_hex_dump(ptr, exts_hash, ngx_ssl_ja4_hex_hash_len / 2);

    /* end */
    c->ssl->fp_ja4_str.len = ptr - c->ssl->fp_ja4_str.data;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja4: ja4 str=[%V], len=[%d]", &c->ssl->fp_ja4_str, c->ssl->fp_ja4_str.len);

    return NGX_OK;
}

/**
 * Params:
 *      c and h2c should be a valid pointers
 *
 * Returns:
 *      NGX_OK -- h2c->fp_str is set
 *      NGX_ERROR -- something went wrong
 */
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c)
{
    unsigned char *pstr = NULL;
    unsigned short n = 0;
    size_t i;

    if (h2c->fp_str.len > 0) {
        return NGX_OK;
    }

    n = 4 + h2c->fp_settings.len * 3
        + 10 + h2c->fp_priorities.len * 4
        + h2c->fp_pseudoheaders.len * 2;

    h2c->fp_str.data = ngx_pnalloc(c->pool, n);
    if (h2c->fp_str.data == NULL) {
        /** Else we break a stream */
        return NGX_ERROR;
    }
    pstr = h2c->fp_str.data;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: alloc bytes: [%d]\n", n);

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

    h2c->fp_str.len = pstr - h2c->fp_str.data;

    h2c->fp_fingerprinted = 1;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: http2 fingerprint: [%V], len=[%d]\n", &h2c->fp_str, h2c->fp_str.len);

    return NGX_OK;
}
