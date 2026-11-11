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

Known-issue tests are repros for open upstream bugs: `run.sh` reports
them as XFAIL and does not fail (unless `STRICT=1`); once a fix lands a
test starts passing and is reported as XPASS.  `.github/workflows/tests.yml`
runs the must-pass set as a gate and the open-issue repro in a
non-blocking step that turns green when the issue is fixed.

`tls_client.py` holds the shared machinery (ClientHello builder with
arbitrary extension codes, HTTP/2 frame builders, log parsing); each test
file is standalone-runnable and documented in its docstring.
