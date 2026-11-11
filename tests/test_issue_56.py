#!/usr/bin/env python3
"""Issue #56: ngx_ja3 / ngx_ja4 [on|off] directives.

https://github.com/phuslu/nginx-ssl-fingerprint/issues/56

The directives toggle fingerprint calculation per configuration block
(http, server, location for the http module; main, server for the stream
module), defaulting to on - the multi-tenant opt-out.

tests/nginx.conf defines locations with the directives switched off; this
test requests the default location and each of them and asserts exactly
which variables are empty ("-" in the log) and which still compute:

  /          -> ja3, ja3_hash, greased, ja4 all present
  /noja3/    -> ja3, ja3_hash, greased empty; ja4 unchanged
  /noja4/    -> ja4 empty; ja3, ja3_hash unchanged
  /both-off/ -> everything empty
"""

import sys

from tls_client import (base_extensions, finish, https_conversation,
                        log_marker, log_new_fingerprints, run_conversation,
                        test_args)

REQUESTS = [
    ("/",        "default (both on)"),
    ("/noja3/",  "ngx_ja3 off"),
    ("/noja4/",  "ngx_ja4 off"),
    ("/both-off/", "ngx_ja3 off + ngx_ja4 off"),
]

EMPTY = "-"


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)
    failures = []

    ext = base_extensions()
    for path, name in REQUESTS:
        if not run_conversation(name,
                                https_conversation(
                                    args.host, args.port, ext,
                                    request=("GET %s HTTP/1.0\r\n\r\n"
                                             % path).encode())):
            failures.append("%s: conversation failed" % name)

    fps = log_new_fingerprints(args.log, marker)
    if len(fps) < len(REQUESTS):
        failures.append("expected %d fingerprint log lines, got %d"
                        % (len(REQUESTS), len(fps)))
        return finish("test_issue_56", failures)

    default, noja3, noja4, bothoff = fps[:4]

    for fp in fps:
        print("  ja3=%-2s ja3_hash=%-2s greased=%-2s ja4=%-2s  (h2fp=%s)"
              % (fp.get("ja3", "?"), fp.get("ja3_hash", "?"),
                 fp.get("greased", "?"), fp.get("ja4", "?"),
                 fp.get("h2fp", "?")))

    # default: everything computed
    for key in ("ja3", "ja3_hash", "greased", "ja4"):
        if default.get(key, EMPTY) == EMPTY:
            failures.append("default location: %s is empty" % key)

    # ngx_ja3 off: ja3 trio empty, ja4 intact and equal to the default
    for key in ("ja3", "ja3_hash", "greased"):
        if noja3.get(key, "?") != EMPTY:
            failures.append("ngx_ja3 off: %s should be empty, got %s"
                            % (key, noja3.get(key)))
    if noja3.get("ja4", EMPTY) == EMPTY or noja3["ja4"] != default["ja4"]:
        failures.append("ngx_ja3 off: ja4 should stay computed and equal "
                        "to default (%s vs %s)"
                        % (noja3.get("ja4"), default.get("ja4")))

    # ngx_ja4 off: ja4 empty, ja3 intact and equal to the default
    if noja4.get("ja4", "?") != EMPTY:
        failures.append("ngx_ja4 off: ja4 should be empty, got %s"
                        % noja4.get("ja4"))
    if noja4.get("ja3", EMPTY) == EMPTY or noja4["ja3"] != default["ja3"]:
        failures.append("ngx_ja4 off: ja3 should stay computed and equal "
                        "to default (%s vs %s)"
                        % (noja4.get("ja3"), default.get("ja3")))

    # both off
    for key in ("ja3", "ja3_hash", "greased", "ja4"):
        if bothoff.get(key, "?") != EMPTY:
            failures.append("ngx_ja3+ngx_ja4 off: %s should be empty, "
                            "got %s" % (key, bothoff.get(key)))

    return finish("test_issue_56", failures)


if __name__ == "__main__":
    sys.exit(main())
