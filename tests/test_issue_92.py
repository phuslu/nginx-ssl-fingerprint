#!/usr/bin/env python3
"""Issue #92: encrypted_client_hello (0xfe0d) and ALPS 17613 are dropped.

https://github.com/phuslu/nginx-ssl-fingerprint/issues/92

Chrome 148 is fingerprinted two extensions short of the truth: apart from
ALPS 17613 (issue #84) the encrypted_client_hello extension 0xfe0d is
also missing, because OpenSSL has no ext_defs slot for it either — e.g.
`t13d1514h2_...` from the module vs `t13d1516h2_...` from tls.peet.ws.

Sends two ClientHellos: a baseline and one carrying exactly the two
extensions from the issue (0xfe0d and 17613).  Both must show up in the
JA3 extension list, and the JA4 extension count must grow by exactly 2
(t13d1514 -> t13d1516 equivalent).

REGRESSION TEST: fixed by the openssl-patch rework that walks the raw
extension packet; guards against the fix regressing.
"""

import sys

from tls_client import (base_extensions, finish, https_conversation,
                        log_marker, log_new_fingerprints, raw_ext,
                        run_conversation, test_args)

ECH = 0xfe0d        # 65037
ALPS_NEW = 17613    # 0x04cd
MISSING = [(ECH, b"\x00\x00"), (ALPS_NEW, b"\x00\x00")]
MISSING_DEC = [str(ECH), str(ALPS_NEW)]


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)
    failures = []

    for name, extra in [("baseline", []),
                        ("ECH 0xfe0d + ALPS 17613 (Chrome-like)", MISSING)]:
        ext = base_extensions()
        for code, payload in extra:
            ext[code] = raw_ext(code, payload)
        if not run_conversation(name,
                                https_conversation(args.host, args.port, ext)):
            failures.append("%s: conversation failed" % name)

    fps = log_new_fingerprints(args.log, marker)
    if len(fps) < 2:
        failures.append("expected 2 fingerprinted requests, got %d" % len(fps))
        return finish("test_issue_92", failures)

    base, unk = fps[0], fps[1]
    print("  baseline   ja3 = %s" % base["ja3"])
    print("  baseline   ja4 = %s" % base["ja4"])
    print("  ECH+ALPS   ja3 = %s" % unk["ja3"])
    print("  ECH+ALPS   ja4 = %s" % unk["ja4"])

    unk_exts = unk["ja3"].split(",")[2].split("-")
    for code in MISSING_DEC:
        if code not in unk_exts:
            failures.append("extension %s missing from JA3 (issue #92)" % code)

    if base["ja4"] == unk["ja4"]:
        failures.append("JA4 identical for both hellos (issue #92)")
    elif int(unk["ja4"][6:8]) != int(base["ja4"][6:8]) + len(MISSING):
        failures.append("JA4 extension count %s != baseline %s + 2"
                        % (unk["ja4"][6:8], base["ja4"][6:8]))

    return finish("test_issue_92", failures)


if __name__ == "__main__":
    sys.exit(main())
