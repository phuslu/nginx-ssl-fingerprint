#!/usr/bin/env python3
"""Base test: $http2_fingerprint correctness on a controlled HTTP/2 client.

Speaks a real HTTP/2 conversation over TLS 1.3 (ALPN h2) with hand-crafted
frames so every fingerprint input is known:

  SETTINGS     (2:0)(3:100)(4:65535) in this wire order
  WINDOW_UPDATE connection-level (sid 0) increment 98765
  HEADERS      sid 1, PRIORITY flag (excl=0, depend=0, weight byte 31),
               pseudo-headers in wire order :method :scheme :path :authority

Expected fingerprint (Akamai format as implemented by the module):

  2:0;3:100;4:65535|98765|1:0:0:32|m,s,p,a

  - settings "<id>:<value>" joined by ';' in wire order
  - window update increment
  - priorities "<sid>:<excl>:<depend>:<weight-1>" (weight byte + 1)
  - pseudo-header first letters in wire order
"""

import sys

from tls_client import (finish, h2_conversation, h2_headers, h2_settings,
                        h2_window_update, log_marker, log_new_fingerprints,
                        run_conversation, test_args)

SETTINGS = [(2, 0), (3, 100), (4, 65535)]
WINDOW_UPDATE = 98765

EXPECTED = "2:0;3:100;4:65535|%d|1:0:0:32|m,s,p,a" % WINDOW_UPDATE


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)

    frames = (h2_settings(SETTINGS)
              + h2_window_update(WINDOW_UPDATE)
              + h2_headers(1, priority=(0, 0, 31)))

    if not run_conversation("http/2 controlled frames",
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

    return finish("test_h2fp", failures)


if __name__ == "__main__":
    sys.exit(main())
