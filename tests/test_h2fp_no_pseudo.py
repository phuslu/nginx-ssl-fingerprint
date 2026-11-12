#!/usr/bin/env python3
"""$http2_fingerprint of a request without pseudo-headers keeps 4 sections.

A HEADERS frame that carries only a regular field (no :method, :scheme,
:path, :authority) is rejected by nginx with 400, but the request still
reaches the log phase, so $http2_fingerprint is formatted with an empty
pseudo-header section:

  SETTINGS     (2:0)(3:100)(4:65535)
  WINDOW_UPDATE connection-level increment 98765
  HEADERS      sid 1, PRIORITY flag (excl=0, depend=0, weight byte 31),
               one regular field "user-agent: test", no pseudo-headers

Expected: 2:0;3:100;4:65535|98765|1:0:0:32|  (empty last section).
The formatter used to drop the separator before it instead, logging the
three-section 2:0;3:100;4:65535|98765|1:0:0:32.
"""

import sys

from tls_client import (finish, h2_conversation, h2_headers, h2_settings,
                        h2_window_update, log_marker, log_new_fingerprints,
                        run_conversation, test_args)

SETTINGS = [(2, 0), (3, 100), (4, 65535)]
WINDOW_UPDATE = 98765
NO_PSEUDO = [(b"user-agent", b"test")]

EXPECTED = "2:0;3:100;4:65535|%d|1:0:0:32|" % WINDOW_UPDATE


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)

    frames = (h2_settings(SETTINGS)
              + h2_window_update(WINDOW_UPDATE)
              + h2_headers(1, pseudo=NO_PSEUDO, priority=(0, 0, 31)))

    if not run_conversation("http/2 headers without pseudo-headers",
                            h2_conversation(args.host, args.port, frames)):
        return 1

    fps = log_new_fingerprints(args.log, marker)
    if not fps:
        print("  (no fingerprint log line was written)")
        return 1

    fp = fps[-1]
    h2fp = fp.get("h2fp", "-")
    print("  h2fp     = %s" % h2fp)
    print("  expected = %s" % EXPECTED)

    failures = []
    if h2fp != EXPECTED:
        failures.append("http2 fingerprint mismatch (see above)")

    return finish("test_h2fp_no_pseudo", failures)


if __name__ == "__main__":
    sys.exit(main())
