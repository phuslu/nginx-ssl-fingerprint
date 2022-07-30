# nginx-ssl-fingerprint

A stable nginx module for SSL/TLS ja3 fingerprint, with high [performance](#performance).

## Patches
 - [nginx - save client hello fingerprint](patches/nginx.patch)
 - [openssl - expose client hello data](patches/openssl.1_1_1.patch)

## Documentation

- [How does we gather TLS fingerprint?](./howto.md)


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

```bash

# Clone

$ git clone -b OpenSSL_1_1_1-stable --depth=1 https://github.com/openssl/openssl
$ git clone -b release-1.23.1 --depth=1 https://github.com/nginx/nginx
$ git clone https://github.com/phuslu/nginx-ssl-fingerprint

# Patch

$ patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl.1_1_1.patch
$ patch -p1 -d nginx < nginx-ssl-fingerprint/patches/nginx.patch

# Configure & Build

$ cd nginx
$ ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=$(pwd)/../openssl --add-module=$(pwd)/../nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
$ make

# Test

$ openssl ecparam -genkey -name prime256v1 | tee ../nginx-ssl-fingerprint/cert.pem | openssl req -x509 -nodes -key /dev/stdin -days 366 -subj '/C=US/OU=Web/CN=example.org' | tee -a ../nginx-ssl-fingerprint/cert.pem
$ sudo objs/nginx -c $(pwd)/../nginx-ssl-fingerprint/nginx.conf
$ curl -k https://127.0.0.1:8444
```

## Performance 

### Server

| Type   | Service             | Cores | Memeory(G) |
| ------ | ------------------- | ----- | ---------- |
| Server | nginx with 5 worker | 8     | 8          |
| Client | wrk                 | 8     | 8          |

### Performance Results

```bash
for i in $(seq 1 10); do
    wrk https://localhost/  --latency -t48 -d15 -c2000  >/tmp/wrk.log.$i
done
```

- QPS: Average Req/Second in 10 times
- Latency: Average 50% latency (ms) in 10 times

| WRK Connection | QPS Cost | Origin Req/Sec | Origin Latency | Req/Sec with fingerprint | Latency with fingerprint |
| -------------- | -------- | -------------- | -------------- | ------------------------ | ------------------------ |
| 50             | 4.3%     | 75896.9        | 571.4us        | 72599.5                  | 597.9us                  |
| 100            | 3.2%     | 80044.3        | 1.105          | 77492.3                  | 1.125                    |
| 200            | 5.2%     | 87101.5        | 2.063          | 82601.1                  | 2.144                    |
| 500            | 4.6%     | 93582.7        | 5.048          | 89311.6                  | 5.282                    |
| 1000           | 6.6%     | 96417.9        | 9.802          | 90020.6                  | 10.519                   |
| 1500           | 6.8%     | 95786.3        | 12.688         | 89246                    | 13.868                   |
| 2000           | 5.1%     | 94399.1        | 14.38          | 89553.4                  | 91030.35                 |
