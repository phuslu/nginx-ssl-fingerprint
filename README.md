# nginx-ssl-fingerprint

nginx module for SSL/TLS ja3 fingerprint.

## Description

This module adds new nginx variables for the SSL/TLS ja3 fingerprint.

## Configuration

### Variables

#### $http_ssl_ja3

The ja3 fingerprint for a SSL connection for a HTTP server.

Example:

```
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

## Build

### Patches

 - [nginx - save client hello extensions](patches/nginx.patch)
 - [openssl - expose client hello data](patches/openssl.1_1_1.patch)


### Compilation and test

Build as a common nginx module.

```bash

# Clone

$ git clone https://github.com/phuslu/nginx-ssl-fingerprint
$ git clone -b OpenSSL_1_1_1-stable https://github.com/openssl/openssl
$ git clone -b branches/stable-1.18 https://github.com/nginx/nginx

# Patch

$ patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl.1_1_1.patch
$ patch -p1 -d nginx < nginx-ssl-fingerprint/patches/nginx.patch

# Configure & Build

$ cd nginx
$ ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=$(pwd)/../openssl --add-module=$(pwd)/../nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
$ make

# Test

$ sudo objs/nginx -c $(pwd)/../nginx-ssl-fingerprint/conf/nginx.conf
$ curl -k https://127.0.0.1:8443 | hexdump -C
```
