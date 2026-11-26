#!/usr/bin/env python3
"""Issue #108: ja3_hash_sorted directive — sorted vs wire extension order.

https://github.com/phuslu/nginx-ssl-fingerprint/issues/108

The module's historical behaviour sorts the JA3 extension list (a JA3N
variant); the JA3 specification instead defines the list in ClientHello
wire order.  ja3_hash_sorted (default on) keeps the sorted form, and
`ja3_hash_sorted off` switches the extension field — and therefore the
MD5 hash — to the specification wire order.

tests/nginx.conf maps /wire/ to a location with ja3_hash_sorted off.
This test requests the default location and /wire/ with the same
ClientHello (extensions in wire order 51-43-10-13-50-11) and asserts:

  default:  ja3 extensions 10-11-13-43-50-51 (sorted), hash = md5(ja3)
  /wire/:   ja3 extensions 51-43-10-13-50-11 (wire),   hash = md5(ja3)
  all other ja3 fields (version, ciphers, groups, formats) identical
"""

import sys

from tls_client import (base_extensions, DEFAULT_CIPHERS, ec_point_formats_ext,
                        finish, https_conversation, log_marker,
                        log_new_fingerprints, md5hex, raw_ext, run_conversation,
                        test_args)

CIPHERS = [0x0a0a] + DEFAULT_CIPHERS  # GREASE cipher: filtered, sets flag

WIRE_EXTS = "51-43-10-13-50-11"
SORTED_EXTS = "10-11-13-43-50-51"


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)
    failures = []

    ext = base_extensions()
    ext[11] = ec_point_formats_ext([0])
    ext[0x0a0a] = raw_ext(0x0a0a, b"\x00")  # GREASE extension: filtered

    for name, path in [("default (sorted)", "/"),
                       ("ja3_hash_sorted off (wire order)", "/wire/")]:
        if not run_conversation(name,
                                https_conversation(
                                    args.host, args.port, ext, ciphers=CIPHERS,
                                    request=("GET %s HTTP/1.0\r\n\r\n"
                                             % path).encode())):
            failures.append("%s: conversation failed" % name)

    fps = log_new_fingerprints(args.log, marker)
    if len(fps) < 2:
        failures.append("expected 2 fingerprint log lines, got %d" % len(fps))
        return finish("test_issue_108", failures)

    default, wire = fps[0], fps[1]
    print("  default ja3      = %s" % default.get("ja3", "-"))
    print("  default ja3_hash = %s" % default.get("ja3_hash", "-"))
    print("  wire    ja3      = %s" % wire.get("ja3", "-"))
    print("  wire    ja3_hash = %s" % wire.get("ja3_hash", "-"))

    d_fields = default.get("ja3", "-").split(",")
    w_fields = wire.get("ja3", "-").split(",")

    if len(d_fields) != 5 or d_fields[2] != SORTED_EXTS:
        failures.append("default ja3 extensions %r, expected sorted %s"
                        % (d_fields[2] if len(d_fields) == 5 else d_fields,
                           SORTED_EXTS))
    if len(w_fields) != 5 or w_fields[2] != WIRE_EXTS:
        failures.append("ja3_hash_sorted off: extensions %r, expected wire "
                        "order %s" % (w_fields[2] if len(w_fields) == 5
                                      else w_fields, WIRE_EXTS))

    # only the extension field may differ; everything else is identical
    # and the hash must match the printed string
    for tag, fp in [("default", default), ("wire", wire)]:
        if fp.get("ja3_hash") != md5hex(fp.get("ja3", "")):
            failures.append("%s: ja3_hash %s != md5(%s)"
                            % (tag, fp.get("ja3_hash"), fp.get("ja3")))

    if len(d_fields) == 5 and len(w_fields) == 5:
        if d_fields[:2] != w_fields[:2] or d_fields[3:] != w_fields[3:]:
            failures.append("non-extension ja3 fields differ between the "
                            "sorted and wire forms")
        if sorted(d_fields[2].split("-")) != sorted(w_fields[2].split("-")):
            failures.append("the two extension lists are not permutations "
                            "of each other")

    return finish("test_issue_108", failures)


if __name__ == "__main__":
    sys.exit(main())
