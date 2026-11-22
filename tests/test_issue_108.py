#!/usr/bin/env python3
"""Issue #108: ja3_hash_sorted directive — wire order vs sorted extensions.

https://github.com/phuslu/nginx-ssl-fingerprint/issues/108

The JA3 specification defines the extension list in the order it appears
in the ClientHello; sorting it turns the fingerprint into a JA3N variant.
Since #108 the default is the specification behaviour (wire order), and
`ja3_hash_sorted on` switches the extension field (and therefore the
MD5 hash) to the sorted form.

tests/nginx.conf maps /sorted/ to a location with ja3_hash_sorted on.
This test requests the default location and /sorted/ with the same
ClientHello (extensions in wire order 51-43-10-13-50-11) and asserts:

  default:  ja3 extensions 51-43-10-13-50-11, hash = md5(ja3)
  /sorted/: ja3 extensions 10-11-13-43-50-51, hash = md5(ja3)
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

    for name, path in [("default (wire order)", "/"),
                       ("ja3_hash_sorted on", "/sorted/")]:
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

    default, sorted_fp = fps[0], fps[1]
    print("  default  ja3      = %s" % default.get("ja3", "-"))
    print("  default  ja3_hash = %s" % default.get("ja3_hash", "-"))
    print("  sorted   ja3      = %s" % sorted_fp.get("ja3", "-"))
    print("  sorted   ja3_hash = %s" % sorted_fp.get("ja3_hash", "-"))

    d_fields = default.get("ja3", "-").split(",")
    s_fields = sorted_fp.get("ja3", "-").split(",")

    if len(d_fields) != 5 or d_fields[2] != WIRE_EXTS:
        failures.append("default ja3 extensions %r, expected wire order %s"
                        % (d_fields[2] if len(d_fields) == 5 else d_fields,
                           WIRE_EXTS))
    if len(s_fields) != 5 or s_fields[2] != SORTED_EXTS:
        failures.append("ja3_hash_sorted on: extensions %r, expected sorted %s"
                        % (s_fields[2] if len(s_fields) == 5 else s_fields,
                           SORTED_EXTS))

    # only the extension field may differ; everything else is wire order
    # in both forms and the hash must match the printed string
    for tag, fp, fields in [("default", default, d_fields),
                            ("sorted", sorted_fp, s_fields)]:
        if len(fields) == 5 and fp.get("ja3_hash") != md5hex(fp.get("ja3", "")):
            failures.append("%s: ja3_hash %s != md5(%s)"
                            % (tag, fp.get("ja3_hash"), fp.get("ja3")))

    if len(d_fields) == 5 and len(s_fields) == 5:
        if d_fields[:2] != s_fields[:2] or d_fields[3:] != s_fields[3:]:
            failures.append("non-extension ja3 fields differ between the "
                            "default and sorted forms")
        if sorted(d_fields[2].split("-")) != sorted(s_fields[2].split("-")):
            failures.append("the two extension lists are not permutations "
                            "of each other")

    return finish("test_issue_108", failures)


if __name__ == "__main__":
    sys.exit(main())
