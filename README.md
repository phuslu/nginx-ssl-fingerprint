# nginx-ssl-fingerprint

A high performance nginx module for ja3 ja4 and http2 fingerprint.

## Patches
 - [nginx - save ja3/ja4/http2 fingerprint](patches)
 - [openssl - save clienthello data](patches)

### Support Matrix

|              | openssl-3.5.6 | openssl-3.6.2 | openssl-4.0.0 | boringssl-0.20261105.0 | aws-lc-v5.14.0 |
| ------------ | ------------- | ------------- | ------------- | ---------------------- | -------------- |
| nginx-1.29.8 |    ✅        |     ✅        |               |          ✅            |      ✅        |
| nginx-1.30.0 |    ✅        |     ✅        |               |          ✅            |      ✅        |
| nginx-1.30.7 |    ✅        |     ✅        |               |          ✅            |      ✅        |
| nginx-1.31.7 |    ✅        |     ✅        |               |          ✅            |      ✅        |
| nginx-1.31.9 |    ✅        |     ✅        |               |          ✅            |      ✅        |

#### NOTE about CVE-2026-123633 and CVE-2026-123007:
___nginx-1.30.7 and nginx-1.31.9 are the releases fixing the HTTP/2
vulnerabilities CVE-2026-123633 (use-after-free) and CVE-2026-123007
(send_window integer underflow); their patches carry the same
fingerprint capture logic as the previous supported releases.___

BoringSSL and AWS-LC need no library patch, only the nginx one.

## Configuration

### Directives

| Name    | Default | Context (http)                | Context (stream) | Comments |
| ------- | ------- | ----------------------------- | ---------------- | -------- |
| ngx_ja3 | on      | http, server, location        | stream, server   | Enable/disable the ja3 calculation; when off, `$http_ssl_ja3`, `$http_ssl_ja3_hash`, `$http_ssl_greased` (and the `$stream_ssl_*` counterparts) are not found. |
| ngx_ja4 | on      | http, server, location        | stream, server   | Enable/disable the ja4 calculation; when off, `$http_ssl_ja4` is not found. |

Useful for multi-tenant setups where only some virtual servers or
locations need fingerprints.

```nginx
http {
    server {
        listen                 127.0.0.1:4433 ssl;
        location /healthz/ {
            ngx_ja3 off;             # no fingerprinting on hot probes
            ngx_ja4 off;
        }
    }
}
```

### HTTP module variables

| Name              | Default Value | Comments                 |
| ----------------- | ------------- | ------------------------ |
| http_ssl_greased  | 0             | TLS greased flag.        |
| http_ssl_ja3      | NULL          | The ja3 fingerprint, extensions sorted. |
| http_ssl_ja3_hash | NULL          | The ja3 fingerprint hash.|
| http_ssl_ja4      | NULL          | The ja4 fingerprint.     |
| http2_fingerprint | NULL          | The http2 fingerprint.   |

#### Example

```nginx
http {
    server {
        listen                 127.0.0.1:4433 ssl;
        http2                  on;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 200 "ja3: $http_ssl_ja3\nja4: $http_ssl_ja4\nh2fp: $http2_fingerprint";
    }
}
```

The ja3 string lists the extensions in ascending order, not in the wire order
of the original JA3: Chromium based browsers shuffle the extensions on every
connection, so the original JA3 of such a client never repeats. For clients
that do not shuffle, the value differs from the one other JA3 tools print.

### Stream module variables

| Name                | Default Value | Comments                 |
| ------------------- | ------------- | ------------------------ |
| stream_ssl_greased  | 0             | TLS greased flag.        |
| stream_ssl_ja3      | NULL          | The ja3 fingerprint, extensions sorted. |
| stream_ssl_ja3_hash | NULL          | The ja3 fingerprint hash.|
| stream_ssl_ja4      | NULL          | The ja4 fingerprint.     |

#### Example

```nginx
stream {
    server {
        listen                 127.0.0.1:4443 ssl;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 "ja4: $stream_ssl_ja4\n";
    }
}
```


## Quick Start

```bash

# Clone

$ git clone -b openssl-3.6.2 --depth=1 https://github.com/openssl/openssl
$ git clone -b release-1.31.9 --depth=1 https://github.com/nginx/nginx
$ git clone -b master https://github.com/phuslu/nginx-ssl-fingerprint

# Patch

$ patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl-3.6.2.patch
$ patch -p1 -d nginx < nginx-ssl-fingerprint/patches/release-1.31.9.patch

# Build

$ cd nginx
$ ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=$(pwd)/../openssl --add-module=$(pwd)/../nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-http_v2_module --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer -DNGX_DEBUG_PALLOC=1" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
$ make

# Test

$ objs/nginx -p . -c $(pwd)/../nginx-ssl-fingerprint/nginx.conf
$ curl -k https://127.0.0.1:4433

# Fuzzing

$ git clone https://github.com/tlsfuzzer/tlsfuzzer
$ cd tlsfuzzer
$ python3 -m venv venv
$ venv/bin/pip install --pre tlslite-ng
$ PYTHONPATH=. venv/bin/python scripts/test-client-hello-max-size.py

```

### BoringSSL / AWS-LC

No `--with-openssl` and no library patch: install the library into a prefix
and point nginx at it. The library build needs cmake, ninja, go and perl.
On these libraries the patched nginx links only together with the module.

```bash

# Clone (AWS-LC: git clone -b v5.14.0 --depth=1 https://github.com/aws/aws-lc tls)

$ git clone -b 0.20261105.0 --depth=1 https://github.com/google/boringssl tls
$ git clone -b release-1.31.9 --depth=1 https://github.com/nginx/nginx
$ git clone -b master https://github.com/phuslu/nginx-ssl-fingerprint

# Build the library

$ cmake -S tls -B tls/build -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX="$(pwd)/tls-install" -DCMAKE_INSTALL_LIBDIR=lib
$ ninja -C tls/build
$ cmake --install tls/build

# Patch

$ patch -p1 -d nginx < nginx-ssl-fingerprint/patches/release-1.31.9.patch

# Build

$ cd nginx
$ ASAN_OPTIONS=symbolize=1 ./auto/configure --add-module="$(pwd)/../nginx-ssl-fingerprint" --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-http_v2_module --with-cc-opt="-I$(pwd)/../tls-install/include -fsanitize=address -O -fno-omit-frame-pointer -DNGX_DEBUG_PALLOC=1" --with-ld-opt="-L$(pwd)/../tls-install/lib -Wl,-E -lasan -Wl,--start-group -lssl -lcrypto -lstdc++ -Wl,--end-group -lpthread"
$ make

```

Differences from OpenSSL:

- On AWS-LC no fingerprint is recorded when nginx rejects the handshake at SNI (e.g. `ssl_reject_handshake on`); OpenSSL and BoringSSL record one.
- On BoringSSL and AWS-LC no fingerprint is recorded for a ClientHello that the library itself rejects before any callback (e.g. a malformed `server_name` or `encrypted_client_hello` extension); OpenSSL records one.

## Peformance

A Performance result as below, check github [actions][actions] for more results and details.
```
------------- Nginx Baseline -------------
Running 30s test @ https://127.0.0.1:4433
  2 threads and 2000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    19.54ms   26.60ms 626.85ms   98.89%
    Req/Sec    37.26k     3.06k   44.23k    82.94%
  2155428 requests in 30.07s, 2.31GB read
Requests/sec:  71669.13
Transfer/sec:     78.81MB

------------- Nginx With Fingerprint -------------
Running 30s test @ https://127.0.0.1:4433
  2 threads and 2000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    21.03ms   26.36ms 618.44ms   98.63%
    Req/Sec    37.45k     3.49k   45.50k    77.80%
  2162578 requests in 30.07s, 2.22GB read
Requests/sec:  71909.53
Transfer/sec:     75.44MB
```
The results indicate that nginx-ssl-fingerprint module performs comparably well.

[actions]: https://github.com/phuslu/nginx-ssl-fingerprint/actions/workflows/performance.yml
