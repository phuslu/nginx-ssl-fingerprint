#!/usr/bin/env python3
"""Configuration-context tests for the ja3_hash_sorted directive.

Starts its own nginx with a purpose-built configuration so that every
supported context and the merge chain can be exercised against one
binary:

  http {}        ja3_hash_sorted off           -> server A inherits off
  server {}      ja3_hash_sorted on (server B) -> overrides http-level off
  location {}    on / off locations on both servers
  "if" in location: if ($arg_s) { ja3_hash_sorted on; }  (only when the
                binary has the rewrite module; probed with nginx -t and
                skipped otherwise, since test builds may use
                --without-http_rewrite_module)
  stream {}      off at stream level           -> server S1 inherits off
  stream server  ja3_hash_sorted on (S2)       -> overrides stream level

Every request uses the same ClientHello (extensions in wire order
51-43-10-13-50-11), so the observed extension field tells the resolved
setting: sorted (on) or wire order (off).  The http log includes
$request so lines map back to paths; the stream servers log to separate
files.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from tls_client import (base_extensions, DEFAULT_CIPHERS, ec_point_formats_ext,
                        finish, https_conversation, raw_ext, run_conversation,
                        test_args)

CIPHERS = [0x0a0a] + DEFAULT_CIPHERS
WIRE_EXTS = "51-43-10-13-50-11"
SORTED_EXTS = "10-11-13-43-50-51"

def _cert_lines():
    """The embedded certificate lines, taken verbatim from nginx.conf."""
    import re
    conf = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "nginx.conf")).read()
    key = re.search(r'^\s*ssl_certificate_key\s+"data:.*?";', conf,
                    re.M | re.S).group(0).strip()
    cert = re.search(r'^\s*ssl_certificate\s+"data:.*?";', conf,
                     re.M | re.S).group(0).strip()
    return key, cert


CERT_KEY, CERT = _cert_lines()

MAIN_CONF = """
worker_processes  1;
daemon off;
pid nginx.pid;
error_log error.log warn;

events {{
    worker_connections  256;
}}

http {{
    ja3_hash_sorted off;

    log_format ctx '$server_port $request ja3=$http_ssl_ja3';

    server {{
        listen                 127.0.0.1:{port_a} ssl;
        access_log             logs/http.log ctx;
        {cert_key}
        {cert}
        root html;

        location / {{                          # inherits http-level off
        }}

        location /on/ {{                       # location on over main off
            ja3_hash_sorted on;
        }}

        location /off/ {{                      # explicit off (redundant)
            ja3_hash_sorted off;
        }}
{if_block}    }}

    server {{
        listen                 127.0.0.1:{port_b} ssl;
        ja3_hash_sorted on;                    # server on over main off
        access_log             logs/http.log ctx;
        {cert_key}
        {cert}
        root html;

        location / {{                          # inherits server-level on
        }}

        location /off/ {{                      # location off over server on
            ja3_hash_sorted off;
        }}
    }}
}}

stream {{
    ja3_hash_sorted off;

    log_format sctx 'ja3=$stream_ssl_ja3';

    server {{
        listen                 127.0.0.1:{stream_a} ssl;
        access_log             logs/stream_off.log sctx;
        {cert_key}
        {cert}
        return "x";
    }}

    server {{
        listen                 127.0.0.1:{stream_b} ssl;
        ja3_hash_sorted on;
        access_log             logs/stream_on.log sctx;
        {cert_key}
        {cert}
        return "x";
    }}
}}
"""

IF_BLOCK = """
        location /if/ {
            if ($arg_s) {
                ja3_hash_sorted on;
            }
        }
"""

PROBE_CONF = """
events { }
http {
    server {
        listen 127.0.0.1:8080;
        location / {
            if ($arg_s) {
                ja3_hash_sorted on;
            }
        }
    }
}
"""

PORT_A, PORT_B = 4833, 4834
STREAM_A, STREAM_B = 4843, 4844


def wait_port(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def nginx_t(nginx_bin, conf, prefix):
    path = os.path.join(prefix, "t.conf")
    with open(path, "w") as f:
        f.write(conf)
    r = subprocess.run([nginx_bin, "-t", "-p", prefix, "-c", path],
                       capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout or "").strip()


def stop_nginx(workdir):
    pid_file = os.path.join(workdir, "nginx.pid")
    if os.path.exists(pid_file):
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
            os.kill(pid, 15)
            for _ in range(30):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.1)
                except OSError:
                    break
        except (OSError, ValueError):
            pass


def main():
    args = test_args(__doc__)
    if not args.nginx_bin or not os.access(args.nginx_bin, os.X_OK):
        print("FAIL: --nginx-bin is required (run.sh passes it)")
        return 1

    workdir = tempfile.mkdtemp(prefix="sslfp-ctx.")
    os.makedirs(os.path.join(workdir, "logs"))
    os.makedirs(os.path.join(workdir, "html"))
    with open(os.path.join(workdir, "html", "index.html"), "w") as f:
        f.write("ok\n")

    failures = []
    try:
        if_supported, why = nginx_t(args.nginx_bin, PROBE_CONF, workdir)
        print("  if-context support: %s" % ("yes" if if_supported else
                                            "no (%s)" %
                                            (why.splitlines()[-1]
                                             if why else "unavailable")))

        conf = MAIN_CONF.format(port_a=PORT_A, port_b=PORT_B,
                                stream_a=STREAM_A, stream_b=STREAM_B,
                                cert_key=CERT_KEY, cert=CERT,
                                if_block=IF_BLOCK if if_supported else "")
        ok, why = nginx_t(args.nginx_bin, conf, workdir)
        if not ok:
            print("FAIL: generated config rejected:\n  %s" % why)
            return 1

        conf_path = os.path.join(workdir, "nginx.conf")
        with open(conf_path, "w") as f:
            f.write(conf)
        log = open(os.path.join(workdir, "stdout.log"), "w")
        subprocess.Popen([args.nginx_bin, "-p", workdir, "-c", conf_path],
                         stdout=log, stderr=log)
        for port in (PORT_A, PORT_B, STREAM_A, STREAM_B):
            if not wait_port(port):
                print("FAIL: nginx did not listen on %d; log:" % port)
                with open(os.path.join(workdir, "error.log")) as f:
                    print(f.read())
                return 1

        ext = base_extensions()
        ext[11] = ec_point_formats_ext([0])
        ext[0x0a0a] = raw_ext(0x0a0a, b"\x00")

        http_cases = [
            (PORT_A, "/", "wire", "http{} off, no override"),
            (PORT_A, "/on/", "sorted", "location on over http-level off"),
            (PORT_A, "/off/", "wire", "explicit location off (redundant)"),
            (PORT_B, "/", "sorted", "server on over http-level off"),
            (PORT_B, "/off/", "wire", "location off over server-level on"),
        ]
        if if_supported:
            http_cases += [
                (PORT_A, "/if/", "wire", "if-branch not taken"),
                (PORT_A, "/if/?s=1", "sorted", "if-branch taken: on"),
            ]

        for port, path, want, tag in http_cases:
            run_conversation(tag, https_conversation(
                "127.0.0.1", port, ext, ciphers=CIPHERS,
                request=("GET %s HTTP/1.0\r\n\r\n" % path).encode()))

        for port, tag in [(STREAM_A, "stream{} off"),
                          (STREAM_B, "stream server on")]:
            run_conversation(tag, https_conversation(
                "127.0.0.1", port, ext, ciphers=CIPHERS))

        time.sleep(0.3)

        # ---- http log: request path -> resolved extension order ----
        results = {}
        with open(os.path.join(workdir, "logs", "http.log")) as f:
            for line in f:
                fields = line.split()
                if len(fields) >= 4 and fields[1] == "GET":
                    for val in fields[3:]:
                        if val.startswith("ja3="):
                            results[(fields[0], fields[2])] = val[4:]
                            break

        want_exts = {"wire": WIRE_EXTS, "sorted": SORTED_EXTS}
        for port, path, want, tag in http_cases:
            ja3 = results.get((str(port), path))
            if ja3 is None:
                failures.append("%s: no log line for %s" % (tag, path))
                continue
            exts = ja3.split(",")[2] if ja3.count(",") == 4 else "-"
            print("  %-6s %-12s -> %s" % (want, path, exts))
            if exts != want_exts[want]:
                failures.append("%s: extensions %s, expected %s (%s order)"
                                % (tag, exts, want_exts[want], want))

        # ---- stream logs ----
        for log_name, want, tag in [("stream_off.log", WIRE_EXTS,
                                     "stream{} off"),
                                    ("stream_on.log", SORTED_EXTS,
                                     "stream server on")]:
            log_path = os.path.join(workdir, "logs", log_name)
            if not os.path.exists(log_path):
                failures.append("%s: no log" % tag)
                continue
            with open(log_path) as f:
                lines = [l for l in f.read().splitlines() if "ja3=" in l]
            ja3 = lines[-1].split("ja3=", 1)[1] if lines else "-"
            exts = ja3.split(",")[2] if ja3.count(",") == 4 else "-"
            print("  %-6s stream:%-12s -> %s" % (want.split('-')[0][:6],
                                                 log_name, exts))
            if exts != want:
                failures.append("%s: extensions %s, expected %s"
                                % (tag, exts, want))
    finally:
        stop_nginx(workdir)
        shutil.rmtree(workdir, ignore_errors=True)

    return finish("test_contexts", failures)


if __name__ == "__main__":
    sys.exit(main())
