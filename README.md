# nginx-ssl-fingerprint

A high performance nginx module for ja3 and http2 fingerprint.

## Patches
 - [nginx - save ja3/http2 fingerprint](patches)
 - [openssl - save clienthello data](patches)

### Support Matrix

|            | OpenSSL_1_1_1 | openssl-3.0 | openssl-3.1 | openssl-3.2 |
| -----------| -------------------- | ----------- | ----------- | ----------- |
| nginx-1.20 | ✅ | ✅ | ✅ | ✅ |
| nginx-1.21 | ✅ | ✅ | ✅ | ✅ |
| nginx-1.22 | ✅ | ✅ | ✅ | ✅ |
| nginx-1.23 | ✅ | ✅ | ✅ | ✅ |
| nginx-1.24 | ✅ | ✅ | ✅ | ✅ |
| nginx-1.25 | ✅ | ✅ | ✅ | ✅ |

## Configuration

### HTTP module variables

| Name              | Default Value | Comments                 |
| ----------------- | ------------- | ------------------------ |
| http_ssl_greased  | 0             | TLS greased flag.        |
| http_ssl_ja3      | NULL          | The ja3 fingerprint.     |
| http2_fingerprint | NULL          | The http2 fingerprint.   |

#### Example

```nginx
http {
    server {
        listen                 127.0.0.1:4433 ssl http2;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 200 "ja3: $http_ssl_ja3\nh2fp: $http2_fingerprint";
    }
}
```

### Stream module variables

| Name                | Default Value | Comments                 |
| ------------------- | ------------- | ------------------------ |
| stream_ssl_greased  | 0             | TLS greased flag.        |
| stream_ssl_ja3      | NULL          | The ja3 fingerprint.     |

#### Example

```nginx
stream {
    server {
        listen                 127.0.0.1:4443 ssl;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 "ja3: $stream_ssl_ja3\n";
    }
}
```


## Quick Start

```bash

# Clone

$ git clone -b openssl-3.2 --depth=1 https://github.com/openssl/openssl
$ git clone -b release-1.25.3 --depth=1 https://github.com/nginx/nginx
$ git clone -b master https://github.com/phuslu/nginx-ssl-fingerprint

# Patch

$ patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl.openssl-3.2.patch
$ patch -p1 -d nginx < nginx-ssl-fingerprint/patches/nginx-1.25.patch

# Build

$ cd nginx
$ ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=$(pwd)/../openssl --add-module=$(pwd)/../nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-http_v2_module --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
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
