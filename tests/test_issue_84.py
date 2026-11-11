#!/usr/bin/env python3
"""Issue #84: the new ALPS codepoint 17613 must be fingerprinted.

https://github.com/phuslu/nginx-ssl-fingerprint/issues/84

BoringSSL rotated the application_settings (ALPS) codepoint from the
legacy 17513 to 17613 (Chrome M135+ sends 17613).  The OpenSSL patches
declare only 17513, so 17613 is silently dropped and current Chrome is
fingerprinted as if it sent no ALPS at all.

Sends two ClientHellos: one with the legacy codepoint 17513 and one with
the current codepoint 17613.  Both are ordinary extensions on the wire
and both must appear in the JA3 extension list and raise the JA4
extension count by 1 each.

REGRESSION TEST: fixed by the openssl-patch rework that walks the raw
extension packet; guards against the fix regressing.
"""

import sys

from tls_client import (base_extensions, finish, https_conversation,
                        log_marker, log_new_fingerprints, raw_ext,
                        run_conversation, test_args)

ALPS_LEGACY = 17513   # 0x0461
ALPS_NEW = 17613      # 0x04cd, Chrome M135+


def probe(name, code, args, marker):
    ext = base_extensions()
    ext[code] = raw_ext(code, b"\x00\x00")
    run_conversation(name, https_conversation(args.host, args.port, ext))


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)
    failures = []

    probe("ALPS legacy 17513", ALPS_LEGACY, args, marker)
    probe("ALPS new 17613", ALPS_NEW, args, marker)

    fps = log_new_fingerprints(args.log, marker)
    if len(fps) < 2:
        failures.append("expected 2 fingerprinted requests, got %d" % len(fps))
        return finish("test_issue_84", failures)

    legacy, new = fps[0], fps[1]
    print("  legacy 17513 ja3 = %s" % legacy["ja3"])
    print("  new    17613 ja3 = %s" % new["ja3"])

    for fp, code, tag in [(legacy, str(ALPS_LEGACY), "legacy"),
                          (new, str(ALPS_NEW), "new")]:
        if code not in fp["ja3"].split(",")[2].split("-"):
            failures.append("ALPS %s codepoint %s missing from JA3 "
                            "(issue #84)" % (tag, code))

    if int(new["ja4"][6:8]) != int(legacy["ja4"][6:8]):
        failures.append("JA4 extension counts for 17513 and 17613 hellos "
                        "differ, expected equal (+1 each vs baseline)")

    return finish("test_issue_84", failures)


if __name__ == "__main__":
    sys.exit(main())
