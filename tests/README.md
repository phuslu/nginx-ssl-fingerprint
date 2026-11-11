# tests

Black-box tests for the ja3/ja4/http2 fingerprints: real TLS 1.3
conversations with fully controlled ClientHellos (via
[tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer) +
[tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng)), hand-crafted
HTTP/2 frames, and assertions against the fingerprints nginx writes to
the access log.

## Run

```sh
NGINX_BIN=/path/to/objs/nginx ./run.sh
```

`run.sh` starts nginx with `nginx.conf`, prints http/1.1, http/2 and
stream sanity output and runs every test.  Environment: `NGINX_BIN`
(default `../../nginx/objs/nginx`), `TEST_PORT`/`STREAM_PORT` (4433/4443),
`TESTS` (subset), `STRICT=1` (known-issue tests must pass too).  Python
dependencies are bootstrapped once into `.venv`/`tlsfuzzer`.

## Files

| file              | class        | verifies |
| ----------------- | ------------ | -------- |
| `test_ja3.py`     | must pass    | exact JA3 string + MD5 hash + greased flag of a known ClientHello (GREASE filtering, sorted extension list) |
| `test_ja4.py`     | must pass    | exact JA4 of a known ClientHello, hashes recomputed independently per the JA4 algorithm |
| `test_h2fp.py`    | must pass    | exact HTTP/2 fingerprint of a controlled SETTINGS/WINDOW_UPDATE/HEADERS sequence |
| `repro_86.py`     | must pass    | regression for [#86](https://github.com/phuslu/nginx-ssl-fingerprint/issues/86) (fixed): extensions unknown to OpenSSL are fingerprinted |
| `test_issue_84.py`| must pass    | regression for [#84](https://github.com/phuslu/nginx-ssl-fingerprint/issues/84) (fixed): the new ALPS codepoint 17613 is fingerprinted |
| `test_issue_92.py`| must pass    | regression for [#92](https://github.com/phuslu/nginx-ssl-fingerprint/issues/92) (fixed): ECH 0xfe0d + ALPS 17613 (Chrome-like) are fingerprinted |
| `test_issue_56.py`| must pass    | [#56](https://github.com/phuslu/nginx-ssl-fingerprint/issues/56): `ngx_ja3`/`ngx_ja4` directives disable the right variables per location |
| `test_issue_82.py`| must pass  | [#82](https://github.com/phuslu/nginx-ssl-fingerprint/issues/82): the h2 fingerprint must be per-request on multiplexed connections |

Known-issue tests are repros for open upstream bugs: `run.sh` reports
them as XFAIL and does not fail (unless `STRICT=1`); once a fix lands a
test starts passing and is reported as XPASS.  `.github/workflows/tests.yml`
runs the must-pass set as a gate and the open-issue repro in a
non-blocking step that turns green when the issue is fixed.

`tls_client.py` holds the shared machinery (ClientHello builder with
arbitrary extension codes, HTTP/2 frame builders, log parsing); each test
file is standalone-runnable and documented in its docstring.
