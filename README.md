# nginx-ssl-fingerprint

A high performance nginx module for ja3 and http2 fingerprint.

## Patches
 - [nginx - save ja3/http2 fingerprint](patches/nginx.1_25.patch)
 - [openssl - save clienthello data](patches/openssl.3_2.patch)

## Configuration

### Variables

| Name              | Default Value | Comments                 |
| ----------------- | ------------- | ------------------------ |
| http_ssl_greased  | 0             | TLS greased flag.        |
| http_ssl_ja3      | NULL          | The ja3 fingerprint.     |
| http2_fingerprint | NULL          | The http2 fingerprint.   |

#### Example

```nginx
http {
    server {
        listen                 127.0.0.1:8443 ssl http2;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 200 "ja3: $http_ssl_ja3\nh2fp: $http2_fingerprint";
    }
}
```

## Quick Start

```bash

# Clone

$ git clone -b openssl-3.2 --depth=1 https://github.com/openssl/openssl
$ git clone -b release-1.25.3 --depth=1 https://github.com/nginx/nginx
$ git clone https://github.com/phuslu/nginx-ssl-fingerprint

# Patch

$ patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl.3_2.patch
$ patch -p1 -d nginx < nginx-ssl-fingerprint/patches/nginx.1_25.patch

# Configure & Build

$ cd nginx
$ ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=$(pwd)/../openssl --add-module=$(pwd)/../nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-http_v2_module --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
$ make

# Test

$ objs/nginx -p . -c $(pwd)/../nginx-ssl-fingerprint/nginx.conf
$ curl -k https://127.0.0.1:8444
```
