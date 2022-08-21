#!/bin/bash

set -ex

LOGS_DIR=/build/nginx-ssl-fingerprint/docker/tests/run/logs

mkdir -p $LOGS_DIR
rm -rf $LOGS_DIR/debug.log $LOGS_DIR/error.log $LOGS_DIR/access.log > /dev/null 2>&1 || true

/build/nginx/objs/nginx -p /build/nginx-ssl-fingerprint/docker/tests/run -c /build/nginx-ssl-fingerprint/docker/tests/nginx.conf &

./wait-for 127.0.0.1:8444 -t 10 -- go test -v -count=1 ./...
