# nginx-ssl-fingerprint

A stable nginx module for SSL/TLS ja3 fingerprint, with high [performance](#performance).

## Patches
 - [nginx - save client hello fingerprint](patches/nginx.patch)
 - [openssl - expose client hello data](patches/openssl.1_1_1.patch)

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

$ objs/nginx -p . -c $(pwd)/../nginx-ssl-fingerprint/nginx.conf
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

v0.2.1

| WRK Connection | QPS Cost | Origin Req/Sec | Origin Latency | Req/Sec with fingerprint | Latency with fingerprint |
| -------------- | -------- | -------------- | -------------- | ------------------------ | ------------------------ |
| 50             | 4.3%     | 75896.9        | 571.4us        | 72599.5                  | 597.9us                  |
| 100            | 3.2%     | 80044.3        | 1.105          | 77492.3                  | 1.125                    |
| 200            | 5.2%     | 87101.5        | 2.063          | 82601.1                  | 2.144                    |
| 500            | 4.6%     | 93582.7        | 5.048          | 89311.6                  | 5.282                    |
| 1000           | 6.6%     | 96417.9        | 9.802          | 90020.6                  | 10.519                   |
| 1500           | 6.8%     | 95786.3        | 12.688         | 89246                    | 13.868                   |
| 2000           | 5.1%     | 94399.1        | 14.38          | 89553.4                  | 91030.35                 |

v0.4.0

| WRK Connection | QPS Cost | Origin Req/Sec | Origin Latency | Req/Sec with fingerprint | Latency with fingerprint |
| -------------- | -------- | -------------- | -------------- | ------------------------ | ------------------------ |
| 50             | 8.60%    | 36795.9        | 1.211          | 33624.2                  | 1.33                  |
| 100            | 8.4%     | 36831.2        | 2.43545        | 33734.6                  | 66.8545                    |
| 200            | 8.39%    | 36862.5        | 4.814          | 33767.2                  | 5.28                    |
| 500            | 8.45     | 36598.8        | 11.827         | 33505.5                  | 12.786                    |
| 1000           | 9.63%    | 33657.1        | 20.877         | 36900.1                  | 20.059                   |
| 1500           | 8.95%    | 36806.3        | 27.591         | 33511                    | 28.155                   |
| 2000           | 8.71%    | 37460.2        | 30.664         | 34194.7                  | 31.504                  |

## TLS Client Hello Packet
```
Frame 103: 561 bytes on wire (4488 bits), 561 bytes captured (4488 bits) on interface utun7, id 0
Null/Loopback
Internet Protocol Version 4, Src: 10.22.76.29, Dst: 143.92.64.129
Transmission Control Protocol, Src Port: 56795, Dst Port: 443, Seq: 1, Ack: 1, Len: 517
    Source Port: 56795
    Destination Port: 443
    [Stream index: 8]
    [Conversation completeness: Complete, WITH_DATA (31)]
    [TCP Segment Len: 517]
    Sequence Number: 1    (relative sequence number)
    Sequence Number (raw): 4163556192
    [Next Sequence Number: 518    (relative sequence number)]
    Acknowledgment Number: 1    (relative ack number)
    Acknowledgment number (raw): 1321024790
    0101 .... = Header Length: 20 bytes (5)
    Flags: 0x018 (PSH, ACK)
    Window: 4096
    [Calculated window size: 262144]
    [Window size scaling factor: 64]
    Checksum: 0xc517 [unverified]
    [Checksum Status: Unverified]
    Urgent Pointer: 0
    [Timestamps]
    [SEQ/ACK analysis]
    TCP payload (517 bytes)
Transport Layer Security
    TLSv1.3 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.0 (0x0301)
        Length: 512
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 508
            Version: TLS 1.2 (0x0303)
            Random: cba554e69ef810c86d3e843f137dc3759fed3f0d6c621f1fb45acb7f92560b48
            Session ID Length: 32
            Session ID: b0a3a558861404d133bc11f9d6b4a4b32b60caaa1559e9332165dc2ac1643d28
            Cipher Suites Length: 32
            Cipher Suites (16 suites)
                Cipher Suite: Reserved (GREASE) (0x6a6a)
                Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
                Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
                Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
                Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
                Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
                Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
                Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
                Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
            Compression Methods Length: 1
            Compression Methods (1 method)
                Compression Method: null (0)
            Extensions Length: 403
            Extension: Reserved (GREASE) (len=0)
                Type: Reserved (GREASE) (27242)
                Length: 0
                Data: <MISSING>
            Extension: server_name (len=29)
                Type: server_name (0)
                Length: 29
                Server Name Indication extension
            Extension: extended_master_secret (len=0)
                Type: extended_master_secret (23)
                Length: 0
            Extension: renegotiation_info (len=1)
                Type: renegotiation_info (65281)
                Length: 1
                Renegotiation Info extension
            Extension: supported_groups (len=10)
                Type: supported_groups (10)
                Length: 10
                Supported Groups List Length: 8
                Supported Groups (4 groups)
            Extension: ec_point_formats (len=2)
                Type: ec_point_formats (11)
                Length: 2
                EC point formats Length: 1
                Elliptic curves point formats (1)
            Extension: session_ticket (len=0)
                Type: session_ticket (35)
                Length: 0
                Data (0 bytes)
            Extension: application_layer_protocol_negotiation (len=14)
                Type: application_layer_protocol_negotiation (16)
                Length: 14
                ALPN Extension Length: 12
                ALPN Protocol
            Extension: status_request (len=5)
                Type: status_request (5)
                Length: 5
                Certificate Status Type: OCSP (1)
                Responder ID list Length: 0
                Request Extensions Length: 0
            Extension: signature_algorithms (len=18)
                Type: signature_algorithms (13)
                Length: 18
                Signature Hash Algorithms Length: 16
                Signature Hash Algorithms (8 algorithms)
            Extension: signed_certificate_timestamp (len=0)
                Type: signed_certificate_timestamp (18)
                Length: 0
            Extension: key_share (len=43)
                Type: key_share (51)
                Length: 43
                Key Share extension
            Extension: psk_key_exchange_modes (len=2)
                Type: psk_key_exchange_modes (45)
                Length: 2
                PSK Key Exchange Modes Length: 1
                PSK Key Exchange Mode: PSK with (EC)DHE key establishment (psk_dhe_ke) (1)
            Extension: supported_versions (len=7)
                Type: supported_versions (43)
                Length: 7
                Supported Versions length: 6
                Supported Version: Reserved (GREASE) (0x7a7a)
                Supported Version: TLS 1.3 (0x0304)
                Supported Version: TLS 1.2 (0x0303)
            Extension: compress_certificate (len=3)
                Type: compress_certificate (27)
                Length: 3
                Algorithms Length: 2
                Algorithm: brotli (2)
            Extension: application_settings (len=5)
                Type: application_settings (17513)
                Length: 5
                ALPS Extension Length: 3
                Supported ALPN List
                    Supported ALPN Length: 2
                    Supported ALPN: h2
            Extension: Reserved (GREASE) (len=1)
                Type: Reserved (GREASE) (64250)
                Length: 1
                Data: 00
            Extension: padding (len=191)
                Type: padding (21)
                Length: 191
                Padding Data: 000000000000000000000000000000000000000000000000000000000000000000000000…
            [JA3 Fullstring: 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0]
            [JA3: cd08e31494f9531f560d64c695473da9]

```

### Ja3

As we know that,  we canJA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence.

This module adds new nginx variables for the SSL/TLS ja3 fingerprint. For more information, please see the [salesforce ja3](https://github.com/salesforce/ja3)

JA3 take 5 fields from TLS Client Hello packet ([example client-hello](./clien-hello.pcap)), each filed convert to decimal and join by '-', then the 5 fields string join by  ','   and then get the ja3 full string.

The ja3 full string's length is not fixed, it's hard to compare. So finally hash the ja3 full string to md5 for easy store or compare.

One Ja3 full string contains 5 parts:

- `TLSVersion`: convert the hex to decimal
- `Ciphers`: convert the hex to decimal and join by '-'
- `Extensions`: use type value and join by '-'  (it's decimal, no need to convert)
- `Supported Groups/Elliptic_Curves`: convert hex to decimal and join by '-'  (exclude Reserved GREASE )
- `EC_Point_Formats`: always be 0 or empty (needs to confirm more details)

### Field 1 - TLSVersion

• TLS Record - Version: minimum supported TLS version (in TLS 1.2 and before). In TLS 1.3, this field is not really used and MUST be 0x0303 ("TLS 1.2") or 0x301 ("TLS 1.0") for compatibility purposes. Reference: RFC 8446 (page 79)

• Client Hello - Version: maximum supported TLS version (in TLS 1.2 and before). In TLS 1.3, this field is not used but MUST be set to 0x0303 ("TLS 1.2").  Reference: RFC 8446 (4.1.2. Client Hello)

Currently, the nginx-ssl-fingerprint used nginx connection, it means the tls version is negotiated.

We are trying to use another TLSVersion which donot take affect by server side.

### Filed 2 - Ciphers

The filed does not special.
For the new OpenSSL lib, the support ciphers count can reach 30 or higher, such as curl.

### Filed 3 - Extensions

The extensions order is random, but relay on the OpenSSL library.  Every tool has its own SSL lib, so even if restarting the devices, the TLS fingerprint does not change.

|OpenSSL ID | Extension name| Remark|
|------ | ------ | ------ |
|0| TLSEXT_TYPE_server_name| |
|5| TLSEXT_TYPE_status_request |patched after v0.3.0|
|10| TLSEXT_TYPE_supported_groups||
|11| TLSEXT_TYPE_ec_point_formats||
|13| TLSEXT_TYPE_signature_algorithms | |
|16| TLSEXT_TYPE_application_layer_protocol_negotiation ||
|18| TLSEXT_TYPE_signed_certificate_timestamp||
|21|TLSEXT_TYPE_padding||
|23| TLSEXT_TYPE_extended_master_secret| |
|27|TLSEXT_TYPE_compress_certificate|patched|
|28|TLSEXT_TYPE_record_size_limit|pathed|
|35| TLSEXT_TYPE_session_ticket ||
|43| TLSEXT_TYPE_supported_versions||
|45|TLSEXT_TYPE_psk_kex_modes||
|51| TLSEXT_TYPE_key_share||
|17513|TLSEXT_TYPE_application_settings|patched after v0.3.0|
|0xff01|TLSEXT_TYPE_renegotiate| |
|-|Reserved||Ignore this extension|


`TLSEXT_TYPE_supported_groups` and `TLSEXT_TYPE_elliptic_curves` they are same filed. More details refer:
https://github.com/openssl/openssl/blob/master/include/openssl/tls1.h#L102-L103


### Filed 4 - EllipticCurves

The filed use extensions `TLSEXT_TYPE_supported_groups`(`TLSEXT_TYPE_elliptic_curves`) supported group value, and convert to integer.

### Filed 5 - EllipticCurvePointFormats

The filed use extensions `TLSEXT_TYPE_ec_point_formats` value, and convert to int.
