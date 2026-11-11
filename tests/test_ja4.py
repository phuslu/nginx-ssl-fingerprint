#!/usr/bin/env python3
"""Base test: $http_ssl_ja4 correctness against an independent JA4 build.

Sends the same controlled ClientHello as test_ja3 (no SNI, no ALPN):

  ciphers [0x0a0a(GREASE), 0x1301, 0x00ff]; extensions (wire order)
  key_share(0x0033), supported_versions(0x002b), supported_groups(0x000a),
  signature_algorithms(0x000d), signature_algorithms_cert(0x0032),
  ec_point_formats(0x000b); sigalgs wire order [0x0804, 0x0403]

and builds the expected JA4 string here per the JA4 algorithm as
implemented by the module (ciphers and extensions sorted, SNI/ALPN
excluded from the extension hash but counted, signature algorithms in
wire order per #83):

  t13i<CC><EE>00_<sha256(ciphers)[:12]>_<sha256(exts_sigalgs)[:12]>

The hashes are computed independently with hashlib, so this test verifies
the module's JA4 section counters and both truncated SHA-256 hashes.
"""

import sys

from tls_client import (DEFAULT_CIPHERS, base_extensions, ec_point_formats_ext,
                        finish, https_conversation, log_marker,
                        log_new_fingerprints, run_conversation, sha12,
                        test_args)

CIPHERS = [0x0a0a] + DEFAULT_CIPHERS  # GREASE filtered, not counted

CIPHER_HASH_INPUT = "00ff,1301"          # sorted non-GREASE ciphers
EXTS_HASH_INPUT = ("000a,000b,000d,002b,0032,0033"  # sorted, no SNI/ALPN
                   "_0804,0403")         # sigalgs in wire order (#83)

EXPECTED_JA4 = "t13i020600_%s_%s" % (sha12(CIPHER_HASH_INPUT),
                                     sha12(EXTS_HASH_INPUT))


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)

    ext = base_extensions()
    ext[11] = ec_point_formats_ext([0])

    if not run_conversation("ja4 known ClientHello",
                            https_conversation(args.host, args.port, ext,
                                               ciphers=CIPHERS)):
        return 1

    fps = log_new_fingerprints(args.log, marker)
    if not fps:
        print("  (no fingerprint log line was written)")
        return 1

    fp = fps[-1]
    ja4 = fp.get("ja4", "-")
    print("  ja4      = %s" % ja4)
    print("  expected = %s" % EXPECTED_JA4)

    failures = []
    if ja4 != EXPECTED_JA4:
        failures.append("ja4 mismatch (see above)")

    return finish("test_ja4", failures)


if __name__ == "__main__":
    sys.exit(main())
