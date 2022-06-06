# nginx-ssl-fingerprint

A stable nginx module for SSL/TLS ja3 fingerprint, with high [performance](docs/performance.md).

 - [nginx - save client hello extensions](patches/nginx.patch)
 - [openssl - expose client hello data](patches/openssl.1_1_1.patch)

## Description

This module adds new nginx variables for the SSL/TLS ja3 fingerprint.
For more information, please see the [salesforce ja3](https://github.com/salesforce/ja3)

## Configuration

### Variables

| Name              | Default Value | Comments                                                    |
| ----------------- | ------------- | ----------------------------------------------------------- |
| http_ssl_greased  | 0             | Chrome grease flag                                          |
| http_ssl_ja3      | NULL          | The ja3 fingerprint for a SSL connection for a HTTP server. |
| http_ssl_ja3_hash | NULL          | ja3 md5 hash                                                |

#### Example

```nginx
http {
    server {
        listen                 127.0.0.1:8443 ssl;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 200 "$http_ssl_ja3";
    }
}
```

## Quick Start

Build as a common nginx module.

### Build and run by docker. (Easy to build, but the compile cost too much time - about 7 minutes  every time)

```bash
$ make docker

$ curl -k https://127.0.0.1:8444
```

### Or build step by step. (Cache the nginx compile objs, so it verfy fast than docker build)

```bash

# Clone

$ git clone -b OpenSSL_1_1_1-stable https://github.com/openssl/openssl
$ git clone -b branches/stable-1.18 https://github.com/nginx/nginx
$ git clone https://github.com/phuslu/nginx-ssl-fingerprint

# Patch

$ patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl.1_1_1.patch
$ patch -p1 -d nginx < nginx-ssl-fingerprint/patches/nginx.patch

# Configure & Build

$ cd nginx
$ ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=$(pwd)/../openssl --add-module=$(pwd)/../nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
$ make

# Test

$ sudo objs/nginx -c $(pwd)/../nginx-ssl-fingerprint/conf/nginx.conf
$ curl -k https://127.0.0.1:8444
```
