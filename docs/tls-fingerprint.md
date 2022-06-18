# Ja3

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

## Field 1 - TLSVersion

• TLS Record - Version: minimum supported TLS version (in TLS 1.2 and before). In TLS 1.3, this field is not really used and MUST be 0x0303 ("TLS 1.2") or 0x301 ("TLS 1.0") for compatibility purposes. Reference: RFC 8446 (page 79)

• Client Hello - Version: maximum supported TLS version (in TLS 1.2 and before). In TLS 1.3, this field is not used but MUST be set to 0x0303 ("TLS 1.2").  Reference: RFC 8446 (4.1.2. Client Hello)

Currently, the nginx-ssl-fingerprint used nginx connection, it means the tls version is negotiated.

We are trying to use another TLSVersion which donot take affect by server side.

## Filed 2 - Ciphers

The filed does not special.
For the new OpenSSL lib, the support ciphers count can reach 30 or higher, such as curl.

## Filed 3 - Extensions

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



## Filed 4 - EllipticCurves

The filed use extensions `TLSEXT_TYPE_supported_groups`(`TLSEXT_TYPE_elliptic_curves`) supported group value, and convert to integer.


## Filed 5 - EllipticCurvePointFormats

The filed use extensions `TLSEXT_TYPE_ec_point_formats` value, and convert to int.
