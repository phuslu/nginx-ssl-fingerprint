#!/usr/bin/env python3
"""Base test: $http_ssl_ja3 / $http_ssl_ja3_hash / greased flag correctness.

Sends one ClientHello with fully controlled, known content:

  version 0x0303, ciphers [0x0a0a(GREASE), 0x1301, 0x00ff],
  extensions (wire order) key_share(51), supported_versions(43),
  supported_groups(10), signature_algorithms(13),
  signature_algorithms_cert(50), ec_point_formats(11),
  groups [x25519(29)], formats [0]

and asserts the exact expected JA3 string — GREASE cipher removed from
the cipher list and the greased flag set, extension list sorted ascending
with GREASE extensions removed (the module's ja3 rework, #94), groups and
point formats in wire order — plus its MD5 hash.
"""

import sys

from tls_client import (base_extensions, DEFAULT_CIPHERS, ec_point_formats_ext,
                        https_conversation, finish, log_marker,
                        log_new_fingerprints, md5hex, raw_ext, run_conversation,
                        test_args)

# GREASE cipher first: must be filtered from the ja3 cipher list and set
# the greased flag; extensions are sent in wire order 51-43-10-13-50-11
# (plus a GREASE extension) but ja3 prints them sorted: 10-11-13-43-50-51
CIPHERS = [0x0a0a] + DEFAULT_CIPHERS

EXPECTED_JA3 = "771,4865-255,10-11-13-43-50-51,29,0"


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)

    ext = base_extensions()
    ext[11] = ec_point_formats_ext([0])
    ext[0x0a0a] = raw_ext(0x0a0a, b"\x00")  # GREASE extension: filtered too

    if not run_conversation("ja3 known ClientHello",
                            https_conversation(args.host, args.port, ext,
                                               ciphers=CIPHERS)):
        return 1

    fps = log_new_fingerprints(args.log, marker)
    failures = []
    if not fps:
        print("  (no fingerprint log line was written)")
        return 1

    fp = fps[-1]
    ja3 = fp.get("ja3", "-")
    print("  ja3      = %s" % ja3)
    print("  ja3_hash = %s" % fp.get("ja3_hash", "-"))
    print("  greased  = %s" % fp.get("greased", "-"))

    if ja3 != EXPECTED_JA3:
        failures.append("ja3 is\n    %s\n  expected\n    %s"
                        % (ja3, EXPECTED_JA3))
    if fp.get("ja3_hash", "-") != md5hex(EXPECTED_JA3):
        failures.append("ja3_hash %s != md5(%r) = %s"
                        % (fp.get("ja3_hash"), EXPECTED_JA3,
                           md5hex(EXPECTED_JA3)))
    if fp.get("greased", "-") != "1":
        failures.append("greased flag is %s, expected 1 (GREASE cipher sent)"
                        % fp.get("greased"))

    return finish("test_ja3", failures)


if __name__ == "__main__":
    sys.exit(main())
