#!/usr/bin/env python3
"""Issue #99: ja3/ja4 list sorting on both sides of the sort threshold.

https://github.com/phuslu/nginx-ssl-fingerprint/issues/99

ngx_ssl_fp_sort_uint16() runs insertion sort for lists of up to 32
entries and heapsort above.  Sends ClientHellos sized so that each sort
call (ja3 extensions, ja4 ciphers, ja4 extensions) gets 32 and 33
entries, plus a long list.  Unknown type codes (0x4000 + i), which the
server ignores, fill the lists up in descending wire order (insertion
sort's worst case): the cipher list is fully descending, the extension
list puts the descending fillers (then ALPN and SNI) ahead of the five
base extensions in their usual order.

  32/33/100 extensions   ja3 and ja4 extension sorts at 32, 33, 100
  32/33/100 ciphers      ja4 cipher sort at 32, 33, 100
  GREASE interleaved     33 extensions and 33 ciphers with GREASE values
                         in between: filtered before the sort
  SNI + ALPN             34 extensions: ja3 sorts 34 (heapsort), ja4
                         drops SNI/ALPN from its list and sorts 32
                         (insertion) but counts 34

Requests hit the /sorted/ location (ja3_hash_sorted on, see #108), so
the ja3 extension field is sorted; with the default (wire order) this
test would compare against the wire sequence instead.

Expected values are built here with sorted():

  ja3   extension field = sorted non-GREASE decimal types joined by '-'
  ja4   the full string, as in test_ja4.py; counts are clamped to 99
"""

import struct
import sys

from tls_client import (alpn_ext, base_extensions, finish,
                        https_conversation, log_marker, log_new_fingerprints,
                        raw_ext, run_conversation, sha12, test_args)

CIPHERS = [0x1301, 0x00ff]  # TLS_AES_128_GCM_SHA256, renegotiation SCSV
SIGALGS = "0804,0403"       # base_extensions() sigalgs, wire order
FILLER = 0x4000             # unassigned codes, no GREASE pattern
SNI, ALPN = 0x0000, 0x0010
ALPN_PROTO = b"http/1.1"    # ja4 alpn chars "h1"


def is_grease(v):
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)


def sni_ext(name):
    entry = b"\x00" + struct.pack(">H", len(name)) + name
    return raw_ext(SNI, struct.pack(">H", len(entry)) + entry)


def interleave(values, every):
    """Insert a distinct GREASE value before every `every`-th entry,
    starting with the first one (clients lead with GREASE)."""
    out = []
    for i, v in enumerate(values):
        if i % every == 0:
            out.append(0x0a0a + 0x1010 * (i // every % 16))
        out.append(v)
    return out


def hello(n_exts, n_ciphers, grease=False, sni_alpn=False):
    """Extensions and ciphers in descending wire order.

    n_exts and n_ciphers count non-GREASE entries.
    """
    fill = n_exts - 5 - (2 if sni_alpn else 0)
    codes = list(range(FILLER + fill - 1, FILLER - 1, -1))
    if grease:
        codes = interleave(codes, 4)

    ext = {}
    for code in codes:
        ext[code] = raw_ext(code, b"")
    if sni_alpn:
        ext[ALPN] = alpn_ext(ALPN_PROTO)
        ext[SNI] = sni_ext(b"localhost")
    ext.update(base_extensions())  # 5 more, codes 10..51

    ciphers = sorted(CIPHERS + [FILLER + i for i in range(n_ciphers - 2)],
                     reverse=True)
    if grease:
        ciphers = interleave(ciphers, 4)

    return ext, ciphers


def expected(exts, ciphers):
    exts = [e for e in exts if not is_grease(e)]
    ciphers = [c for c in ciphers if not is_grease(c)]
    hashed = [e for e in exts if e not in (SNI, ALPN)]

    ja3_exts = "-".join(str(e) for e in sorted(exts))

    ja4 = "t13%s%02d%02d%s_%s_%s" % (
        "d" if SNI in exts else "i",
        min(len(ciphers), 99), min(len(exts), 99),
        "h1" if ALPN in exts else "00",
        sha12(",".join("%04x" % c for c in sorted(ciphers))),
        sha12(",".join("%04x" % e for e in sorted(hashed)) + "_" + SIGALGS))

    return ja3_exts, ja4


CASES = [
    # name,               extensions, ciphers, options
    ("32 extensions",     32,         2,       {}),
    ("33 extensions",     33,         2,       {}),
    ("100 extensions",    100,        2,       {}),
    ("32 ciphers",        5,          32,      {}),
    ("33 ciphers",        5,          33,      {}),
    ("100 ciphers",       5,          100,     {}),
    ("GREASE interleaved", 33,        33,      {"grease": True}),
    ("SNI + ALPN",        34,         2,       {"sni_alpn": True}),
]


def main():
    args = test_args(__doc__)
    marker = log_marker(args.log)
    failures = []
    sent = []

    for name, n_exts, n_ciphers, opts in CASES:
        ext, ciphers = hello(n_exts, n_ciphers, **opts)
        if run_conversation(name, https_conversation(args.host, args.port,
                                                     ext, ciphers=ciphers,
                                                     request=b"GET /sorted/ HTTP/1.0\r\n\r\n")):
            sent.append((name, list(ext), ciphers))
        else:
            failures.append("%s: handshake failed" % name)

    fps = log_new_fingerprints(args.log, marker)
    if len(fps) != len(sent):
        failures.append("expected %d fingerprinted requests, got %d"
                        % (len(sent), len(fps)))
        return finish("test_issue_99", failures)

    for (name, exts, ciphers), fp in zip(sent, fps):
        ja3_exts, ja4 = expected(exts, ciphers)
        fields = fp["ja3"].split(",")
        got_exts = fields[2] if len(fields) == 5 else "-"

        print("  %-18s ja4 = %s" % (name, fp["ja4"]))
        if got_exts != ja3_exts:
            failures.append("%s: ja3 extensions %s, expected %s"
                            % (name, got_exts, ja3_exts))
        if fp["ja4"] != ja4:
            failures.append("%s: ja4 %s, expected %s"
                            % (name, fp["ja4"], ja4))

    return finish("test_issue_99", failures)


if __name__ == "__main__":
    sys.exit(main())
