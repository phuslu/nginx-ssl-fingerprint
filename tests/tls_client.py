"""Shared helpers for the nginx-ssl-fingerprint test suite.

Builds TLS 1.3 conversations with fully controlled ClientHellos (arbitrary
extension lists, including extension types unknown to OpenSSL), HTTP/2
frame sequences, and parses the fingerprint log lines produced by
tests/nginx.conf.

Every test file in this directory is standalone-runnable:

    python3 test_<name>.py [--host 127.0.0.1] [--port 4433] [--log access.log]

and is executed by run.sh against one nginx instance.
"""

from __future__ import print_function

import argparse
import hashlib
import struct

try:
    from tlsfuzzer.runner import Runner
    from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
            ChangeCipherSpecGenerator, FinishedGenerator, \
            ApplicationDataGenerator, AlertGenerator
    from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
            ExpectChangeCipherSpec, ExpectFinished, ExpectApplicationData, \
            ExpectClose, ExpectEncryptedExtensions, ExpectCertificateVerify, \
            ExpectNewSessionTicket, ExpectAlert
    from tlsfuzzer.helpers import key_share_gen, SIG_ALL
    from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
            GroupName, ExtensionType, SignatureScheme
    from tlslite.extensions import TLSExtension, ClientKeyShareExtension, \
            SupportedVersionsExtension, SupportedGroupsExtension, \
            SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
except ImportError as e:
    print("FAIL: missing python dependencies: %s" % e)
    print("      run via tests/run.sh (bootstraps a venv) or:")
    print("      pip install --pre tlslite-ng  &&  "
          "PYTHONPATH=/path/to/tlsfuzzer")
    raise SystemExit(2)


DEFAULT_CIPHERS = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]

DEFAULT_GROUPS = [GroupName.x25519]

# wire order of the "base" extensions is: key_share(51), supported_versions
# (43), supported_groups(10), signature_algorithms(13),
# signature_algorithms_cert(50)
BASE_SIGALGS = [SignatureScheme.rsa_pss_rsae_sha256,     # 0x0804
                SignatureScheme.ecdsa_secp256r1_sha256]  # 0x0403


def base_extensions(groups=None, sigalgs=None):
    """The five extensions a TLS 1.3 handshake to this nginx needs."""
    return {
        ExtensionType.key_share:
            ClientKeyShareExtension().create(
                [key_share_gen(g) for g in (groups or DEFAULT_GROUPS)]),
        ExtensionType.supported_versions:
            SupportedVersionsExtension().create([(3, 4), (3, 3)]),
        ExtensionType.supported_groups:
            SupportedGroupsExtension().create(groups or DEFAULT_GROUPS),
        ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigalgs or BASE_SIGALGS),
        ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(SIG_ALL),
    }


def raw_ext(code, payload):
    """An extension with an arbitrary (possibly unknown) type code."""
    return TLSExtension(extType=code).create(bytearray(payload))


def alpn_ext(proto):
    """ALPN extension advertising one protocol, e.g. b'h2'."""
    return TLSExtension(extType=16).create(
        bytearray(struct.pack(">H", len(proto) + 1) + bytes([len(proto)]) + proto))


def ec_point_formats_ext(formats=(0,)):
    payload = bytes([len(formats)]) + bytes(formats)
    return TLSExtension(extType=11).create(bytearray(payload))


def https_conversation(host, port, extensions, ciphers=None, request=None):
    """TLS 1.3 handshake + one plaintext HTTP/1.x request.

    Returns the ROOT Connect node for Runner().  The request must complete
    so nginx writes the fingerprint access-log line under test.
    """
    root = node = Connect(host, port)
    node = node.add_child(ClientHelloGenerator(
        ciphers or DEFAULT_CIPHERS, extensions=extensions))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(request or b"GET / HTTP/1.0\r\n\r\n")))

    # NewSessionTicket may arrive 0..n times before the response
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)
    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(
        AlertGenerator(AlertLevel.warning, AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    return root


# ---------------------------------------------------------------- HTTP/2 ---

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def h2_frame(ftype, flags, sid, payload):
    return (struct.pack(">I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack(">I", sid) + payload)


def h2_settings(params):
    """SETTINGS frame: params is a list of (id, value) in wire order."""
    return h2_frame(4, 0, 0,
                    b"".join(struct.pack(">HI", i, v) for i, v in params))


def h2_window_update(increment, sid=0):
    return h2_frame(8, 0, sid, struct.pack(">I", increment))


def _hpack_literal(name, value):
    # literal header field without indexing, new name, no huffman
    return b"\x10" + bytes([len(name)]) + name + bytes([len(value)]) + value


PSEUDO_MSPA = [(b":method", b"GET"), (b":scheme", b"https"),
               (b":path", b"/"), (b":authority", b"localhost")]
PSEUDO_MSAP = [(b":method", b"GET"), (b":scheme", b"https"),
               (b":authority", b"localhost"), (b":path", b"/")]


def h2_headers(sid, pseudo=PSEUDO_MSPA, priority=None, end_stream=True):
    """HEADERS frame; priority is (exclusive, depend, weight_byte) or None."""
    payload = b""
    flags = 0x4  # END_HEADERS
    if priority is not None:
        excl, dep, weight = priority
        payload += struct.pack(">I", (excl << 31) | (dep & 0x7fffffff))
        payload += bytes([weight])
        flags |= 0x20  # PRIORITY
    for name, value in pseudo:
        payload += _hpack_literal(name, value)
    if end_stream:
        flags |= 0x1
    return h2_frame(1, flags, sid, payload)


def h2_conversation(host, port, frames, extensions=None, ciphers=None):
    """TLS 1.3 + ALPN h2 handshake + raw HTTP/2 frames in one AppData.

    `frames` is the byte string sent after the connection preface.
    """
    ext = base_extensions()
    ext[16] = alpn_ext(b"h2")
    if extensions:
        ext.update(extensions)

    root = node = Connect(host, port)
    node = node.add_child(ClientHelloGenerator(
        ciphers or DEFAULT_CIPHERS, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(H2_PREFACE + frames)))
    node = node.add_child(
        AlertGenerator(AlertLevel.warning, AlertDescription.close_notify))

    # post-handshake NewSessionTicket(s) may still arrive, then the
    # server SETTINGS/ACK/response as application data; after our
    # close_notify nginx may answer with an alert or just close the TCP
    # connection (response can be discarded), so accept either end
    nst = ExpectNewSessionTicket()
    node = node.add_child(nst)
    node.add_child(nst)

    cycle = ExpectApplicationData()
    nst.next_sibling = cycle
    cycle.add_child(cycle)

    alert = ExpectAlert()
    cycle.next_sibling = alert
    alert.next_sibling = ExpectClose()
    alert.add_child(ExpectClose())
    return root


# ------------------------------------------------------------------ logs ---

LOG_KEYS = ("ja3", "ja3_hash", "ja4", "greased", "h2fp")


def log_marker(path):
    """Number of lines currently in the log; pass to log_new_fingerprints()."""
    try:
        with open(path) as f:
            return sum(1 for _ in f)
    except IOError:
        return 0


def log_new_fingerprints(path, marker):
    """Parsed fingerprint log lines appended after `marker`."""
    with open(path, "r", errors="replace") as f:
        lines = f.readlines()[marker:]
    out = []
    for line in lines:
        fields = line.split()
        fp = {}
        for i, f in enumerate(fields):
            if f.endswith(":") and i + 1 < len(fields) and \
                    f[:-1] in LOG_KEYS:
                fp[f[:-1]] = fields[i + 1]
        if "ja3" in fp and "ja4" in fp:
            out.append(fp)
    return out


def run_conversation(name, root):
    """Run one conversation; returns True on success."""
    try:
        Runner(root).run()
        print("  handshake: %-40s completed" % name)
        return True
    except Exception as e:
        print("  handshake: %-40s FAILED: %s: %s"
              % (name, type(e).__name__, e))
        return False


def test_args(description):
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--log", default="access.log",
                    help="nginx access_log file with the fingerprint format")
    return ap.parse_args()


def finish(name, failures):
    if failures:
        print("FAIL [%s]:" % name)
        for f in failures:
            print("  - %s" % f)
        return 1
    print("PASS [%s]" % name)
    return 0


def md5hex(s):
    return hashlib.md5(s.encode()).hexdigest()


def sha12(s):
    return hashlib.sha256(s.encode()).hexdigest()[:12]
