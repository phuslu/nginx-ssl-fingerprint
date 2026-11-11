#!/usr/bin/env bash
# Test runner for the nginx-ssl-fingerprint test suite.
#
# Starts the compiled nginx with tests/nginx.conf, prints sanity output for
# http/1.1, http/2 and the stream module, then runs every tests/test_*.py
# and tests/repro_*.py file (or the subset given via TESTS).
#
# Test classes:
#   required    test_ja3.py test_ja4.py test_h2fp.py plus regression tests
#               for fixed issues (#86 #84 #92) - must pass on any correct
#               build of the current sources
#   known issues  test_issue_82.py
#               repro for an open upstream issue; expected to FAIL until
#               the corresponding fix lands.  Reported as XFAIL and does
#               not fail this script unless STRICT=1.
#
# Environment:
#   NGINX_BIN   path to the compiled nginx binary
#               (default: <repo>/../../nginx/objs/nginx)
#   TEST_PORT   https port           (default 4433)
#   STREAM_PORT stream module port   (default 4443)
#   TESTS       space-separated list of test files to run (default: all)
#   KNOWN       space-separated list of known-issue test files
#   STRICT=1    known-issue tests must pass too (use after fixes land)
#   PYTHONBIN   reuse an existing python (with tlslite-ng installed and
#               tlsfuzzer importable via PYTHONPATH) instead of the
#               bootstrapped tests/.venv
#
# Python dependencies (tlslite-ng + the tlsfuzzer engine) are bootstrapped
# once into tests/.venv and tests/tlsfuzzer (network needed on first run).

set -u

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$TESTS_DIR")"

NGINX_BIN="${NGINX_BIN:-$(cd "$REPO_DIR/.." && pwd)/nginx/objs/nginx}"
TEST_PORT="${TEST_PORT:-4433}"
STREAM_PORT="${STREAM_PORT:-4443}"
STRICT="${STRICT:-0}"

BASE_TESTS="test_ja3.py test_ja4.py test_h2fp.py repro_86.py test_issue_84.py test_issue_92.py"
KNOWN_TESTS="test_issue_82.py"
TESTS="${TESTS:-$BASE_TESTS $KNOWN_TESTS}"
KNOWN="${KNOWN:-$KNOWN_TESTS}"

[ -x "$NGINX_BIN" ] || { echo "FAIL: nginx binary not found: $NGINX_BIN (set NGINX_BIN)"; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sslfp-test.XXXXXX")"
mkdir -p "$WORK/logs" "$WORK/html"
cp "$TESTS_DIR/html/index.html" "$WORK/html/"
sed -e "s/__TEST_PORT__/$TEST_PORT/" -e "s/__STREAM_PORT__/$STREAM_PORT/" \
    "$TESTS_DIR/nginx.conf" > "$WORK/nginx.conf"

cleanup() {
    if [ -f "$WORK/nginx.pid" ]; then
        kill -QUIT "$(cat "$WORK/nginx.pid")" 2>/dev/null
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$(cat "$WORK/nginx.pid" 2>/dev/null)" 2>/dev/null || break
            sleep 0.3
        done
        kill -TERM "$(cat "$WORK/nginx.pid" 2>/dev/null)" 2>/dev/null
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

echo "== starting nginx: $NGINX_BIN -p $WORK (https://127.0.0.1:$TEST_PORT)"
"$NGINX_BIN" -p "$WORK" -c "$WORK/nginx.conf" > "$WORK/stdout.log" 2>&1 &

wait_port() {
    for _ in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
            exec 3>&- 3<&- || true
            return 0
        fi
        sleep 0.2
    done
    return 1
}

if ! wait_port "$TEST_PORT"; then
    echo "FAIL: nginx did not start; log:"
    cat "$WORK/stdout.log" "$WORK/logs/error.log" "$WORK/error.log" 2>/dev/null
    exit 2
fi

echo "== sanity: http/1.1"
curl -sk --http1.1 -D- -o /dev/null "https://127.0.0.1:$TEST_PORT/" \
    | grep -i '^x-ja3:\|^x-ja4:\|^x-h2fp:' || echo "(no fingerprint headers?)"

echo "== sanity: http/2"
curl -sk --http2 -D- -o /dev/null "https://127.0.0.1:$TEST_PORT/" \
    | grep -i '^x-ja3:\|^x-ja4:\|^x-h2fp:' || echo "(no fingerprint headers?)"

# --- python environment: reuse or bootstrap ---------------------------------
if [ -z "${PYTHONBIN:-}" ]; then
    if [ ! -x "$TESTS_DIR/.venv/bin/python" ]; then
        echo "== bootstrapping python venv in $TESTS_DIR/.venv (first run)"
        python3 -m venv "$TESTS_DIR/.venv" || exit 2
        "$TESTS_DIR/.venv/bin/pip" install --pre --quiet tlslite-ng || exit 2
    fi
    if [ ! -d "$TESTS_DIR/tlsfuzzer" ]; then
        echo "== cloning tlsfuzzer into $TESTS_DIR/tlsfuzzer (first run)"
        git clone --quiet --depth=1 https://github.com/tlsfuzzer/tlsfuzzer \
            "$TESTS_DIR/tlsfuzzer" || exit 2
    fi
    PYTHONBIN="$TESTS_DIR/.venv/bin/python"
    export PYTHONPATH="$TESTS_DIR/tlsfuzzer${PYTHONPATH:+:$PYTHONPATH}"
fi

is_known() {
    for k in $KNOWN; do [ "$k" = "$1" ] && return 0; done
    return 1
}

echo
echo "== running tests"

FAILED=""
XFAILED=""
XPASSED=""

for t in $TESTS; do
    echo "---- $t"
    if "$PYTHONBIN" "$TESTS_DIR/$t" \
        --host 127.0.0.1 --port "$TEST_PORT" --log "$WORK/logs/access.log"
    then
        if is_known "$t" && [ "$STRICT" != "1" ]; then
            echo "RESULT: XPASS ($t: issue seems fixed)"
            XPASSED="$XPASSED $t"
        fi
    else
        if is_known "$t" && [ "$STRICT" != "1" ]; then
            echo "RESULT: XFAIL ($t: known open issue, expected to fail)"
            XFAILED="$XFAILED $t"
        else
            echo "RESULT: FAIL ($t)"
            FAILED="$FAILED $t"
        fi
    fi
done

echo "== stream module sanity"
echo | openssl s_client -connect "127.0.0.1:$STREAM_PORT" 2>/dev/null | head -2
tail -1 "$WORK/logs/stream.log" 2>/dev/null

echo
echo "==================== summary ===================="
echo "failed:  ${FAILED:-none}"
echo "xfailed: ${XFAILED:-none}   (known issues, see file headers)"
echo "xpassed: ${XPASSED:-none}   (known-issue tests that now pass)"
if [ -n "$FAILED" ]; then
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS (known issues xfailed)"
exit 0
