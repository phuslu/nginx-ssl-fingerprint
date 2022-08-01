#!/bin/bash

LOGS_DIR=/build/nginx-ssl-fingerprint/docker/tlsfuzzer/run/logs
SEGV_MSG="AddressSanitizer:DEADLYSIGNAL"

cd /build/tlsfuzzer/ || (echo "cant cd"; exit 1)
mkdir -p $LOGS_DIR
rm -rf $LOGS_DIR/debug.log $LOGS_DIR/error.log $LOGS_DIR/access.log > /dev/null 2>&1 || true

set -o pipefail
python3 /build/tlsfuzzer/tests/scripts_retention.py /build/nginx-ssl-fingerprint/docker/tlsfuzzer/test.json /build/nginx/objs/nginx 0 2>&1 | tee $LOGS_DIR/tlsfuzzer.log
result=$?
set +o pipefail


if [ "$result" != "0" ]
then
  echo '[RESULTS] tlsfuzzer failed'
else 
  echo '[RESULTS] tlsfuzzer ok'
fi

SEGV_COUNT=$(grep -c -i "$SEGV_MSG" $LOGS_DIR/debug.log)
if [ "$SEGV_COUNT" != "0" ]
then
  echo '[RESULTS] segv failed'
  exit 1
else 
  echo '[RESULTS] segv ok'
fi

exit $result
