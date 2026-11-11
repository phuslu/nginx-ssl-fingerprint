#!/usr/bin/env python3
"""Issue #86: extensions unknown to OpenSSL must be fingerprinted.

https://github.com/phuslu/nginx-ssl-fingerprint/issues/86

Two identical TLS 1.3 ClientHellos except the second carries extensions
with types OpenSSL has no ext_defs entry for:

  * 0x7788 (30600 decimal, unassigned) and
  * 0xfe0d (65037 decimal, encrypted_client_hello)

Per JA3/JA4 every extension on the wire is fingerprinted, known or not,
so both hellos must produce different fingerprints: both codes appear in
the JA3 extension list and the JA4 extension count grows by exactly 2.

REGRESSION TEST: fixed by the openssl-patch rework that serializes
`sc->clienthello->extensions` (the raw wire packet) instead of the
parsed pre_proc_exts view; guards against the fix regressing.
"""

import sys

from tls_client import (base_extensions, finish, https_conversation,
                        log_marker, log_new_fingerprints, raw_ext,
                        run_conversation, test_args)

UNKNOWN_EXTS = [(0x7788, b"\x00\x01\x02"), (0xfe0d, b"\x00\x00")]
UNKNOWN_DEC = [str(code) for code, _ in UNKNOWN_EXTS]


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)
    failures = []

    for name, extra in [("baseline", []),
                        ("unknown extensions 0x7788+0xfe0d", UNKNOWN_EXTS)]:
        ext = base_extensions()
        for code, payload in extra:
            ext[code] = raw_ext(code, payload)
        if not run_conversation(name,
                                https_conversation(args.host, args.port, ext)):
            failures.append("%s: conversation failed" % name)

    fps = log_new_fingerprints(args.log, marker)
    if len(fps) < 2:
        failures.append("expected 2 fingerprinted requests, got %d" % len(fps))
        return finish("repro_86", failures)

    base, unk = fps[0], fps[1]
    print("  baseline ja3 = %s" % base["ja3"])
    print("  baseline ja4 = %s" % base["ja4"])
    print("  unknown  ja3 = %s" % unk["ja3"])
    print("  unknown  ja4 = %s" % unk["ja4"])

    base_exts = base["ja3"].split(",")[2].split("-")
    unk_exts = unk["ja3"].split(",")[2].split("-")

    for code in UNKNOWN_DEC:
        if code not in unk_exts:
            failures.append("extension %s missing from JA3 list of the "
                            "unknown-extensions hello (issue #86)" % code)
        if code in base_exts:
            failures.append("extension %s unexpectedly present in baseline"
                            % code)

    if base["ja3"] == unk["ja3"]:
        failures.append("JA3 identical for both hellos (issue #86)")
    if base["ja4"] == unk["ja4"]:
        failures.append("JA4 identical for both hellos (issue #86)")
    elif int(unk["ja4"][6:8]) != int(base["ja4"][6:8]) + len(UNKNOWN_EXTS):
        failures.append("JA4 extension count %s != baseline %s + %d"
                        % (unk["ja4"][6:8], base["ja4"][6:8],
                           len(UNKNOWN_EXTS)))

    return finish("repro_86", failures)


if __name__ == "__main__":
    sys.exit(main())
