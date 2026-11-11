#!/usr/bin/env python3
"""Issue #82: the h2 fingerprint must be per-request, not per-connection.

https://github.com/phuslu/nginx-ssl-fingerprint/issues/82

The module stores the priority/pseudo-header sections of the HTTP/2
fingerprint on the connection struct and freezes them after the first
request, so on a multiplexed connection every subsequent request logs
request 1's HEADERS-priority data.

Sends two requests with deliberately different per-request inputs over
ONE h2 connection:

  request 1 (stream 1): PRIORITY excl=0 depend=0 weight=16,
                         pseudo-headers :method :scheme :path :authority
  request 2 (stream 3): PRIORITY excl=1 depend=7 weight=32,
                         pseudo-headers :method :scheme :authority :path

The connection-scoped sections (SETTINGS, WINDOW_UPDATE) are the same
for both lines; the per-request sections must differ: the second log
line must carry `3:1:7:32|m,s,a,p`, not request 1's values.
"""

import sys

from tls_client import (finish, h2_conversation, h2_headers, h2_settings,
                        h2_window_update, log_marker, log_new_fingerprints,
                        run_conversation, test_args, PSEUDO_MSPA, PSEUDO_MSAP)

SETTINGS = [(2, 0), (3, 100), (4, 65535)]
WINDOW_UPDATE = 98765

REQ1_PRIORITY = "1:0:0:16"   # excl=0 dep=0 weight byte 15
REQ2_PRIORITY = "3:1:7:32"   # sid 3, excl=1, dep=7, weight byte 31
REQ1_PSEUDO = "m,s,p,a"
REQ2_PSEUDO = "m,s,a,p"


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)

    frames = (h2_settings(SETTINGS)
              + h2_window_update(WINDOW_UPDATE)
              + h2_headers(1, pseudo=PSEUDO_MSPA, priority=(0, 0, 15))
              + h2_headers(3, pseudo=PSEUDO_MSAP, priority=(1, 7, 31)))

    if not run_conversation("two multiplexed h2 requests",
                            h2_conversation(args.host, args.port, frames)):
        return 1

    fps = log_new_fingerprints(args.log, marker)
    failures = []
    if len(fps) < 2:
        failures.append("expected 2 fingerprinted requests, got %d" % len(fps))
        return finish("test_issue_82", failures)

    first, second = fps[0], fps[1]
    print("  request 1 h2fp = %s" % first.get("h2fp", "-"))
    print("  request 2 h2fp = %s" % second.get("h2fp", "-"))

    failures = []

    if REQ1_PRIORITY not in first.get("h2fp", ""):
        failures.append("request 1 fingerprint lacks its priority section "
                        "%s" % REQ1_PRIORITY)
    if REQ1_PSEUDO not in first.get("h2fp", ""):
        failures.append("request 1 fingerprint lacks pseudo-headers %s"
                        % REQ1_PSEUDO)

    h2fp2 = second.get("h2fp", "")
    if REQ2_PRIORITY not in h2fp2 or REQ1_PRIORITY in h2fp2.split("|")[2]:
        failures.append("request 2 priority section is request 1's data "
                        "(issue #82): expected %s in %r"
                        % (REQ2_PRIORITY, h2fp2))
    if h2fp2.split("|")[-1] != REQ2_PSEUDO:
        failures.append("request 2 pseudo-header order is request 1's data "
                        "(issue #82): expected %s in %r"
                        % (REQ2_PSEUDO, h2fp2))

    return finish("test_issue_82", failures)


if __name__ == "__main__":
    sys.exit(main())
