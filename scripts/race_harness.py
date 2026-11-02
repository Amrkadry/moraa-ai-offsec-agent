#!/usr/bin/env python3
"""
race_harness.py -- fire N near-simultaneous copies of one HTTP request and group the
responses so a race-condition win (one divergent outcome among N) is unmissable.

WHY: race conditions (double-redeem, fund transfer, vote/rate limits, 2FA bypass) are
proven by a single request out of N landing a DIFFERENT outcome. Done by hand -- or
with an unsynced loop -- the requests land hundreds of milliseconds apart and every
run "passes", so the class just gets skipped. This harness synchronizes with a thread
barrier plus last-byte sync: every worker opens its connection and sends all but the
FINAL byte of the request, blocks on a shared barrier, then releases the final byte
together -- so all N requests are read by the server inside one tick instead of
spread across N.

HTTP/2 NOTE: the state of the art is the H2 single-packet attack (all requests
serialized into one TCP packet on a single H2 connection, as Turbo Intruder does) --
it also beats servers that serialize per-connection request reads. That needs an H2
stack; stdlib-only means raw HTTP/1.1 sockets here. If a race "fails" against an H2
target, re-test with Turbo Intruder single-packet mode before declaring it
unexploitable.

Usage:
  # Burp: right-click request -> "Copy to file", then (Host header picks the target):
  python3 race_harness.py -r req.txt -n 30 --diff

  # or curl-style:
  python3 race_harness.py -X POST https://target/api/redeem \
      -H "Cookie: session=..." -d '{"code":"XMAS"}' -n 20 --diff

Templating: {{i}} anywhere in the request (path, headers, body) is replaced with the
0-based request index -- for one-time codes / unique coupons where every request must
carry a different value but still fire in sync.

Output: responses grouped by (status, body length, sha256[:12] of body); only group
COUNTS are printed, never N full responses. --diff loudly flags and exits non-zero on
any response outside the modal group: that divergence is the whole signal.

Exit: 0 = no divergence observed; 2 = divergence found (--diff); 1 = usage/transport
failure.
"""
import argparse
import hashlib
import socket
import ssl
import sys
import threading
import urllib.parse

DEFAULT_COUNT = 20


def parse_raw_request(raw: bytes):
    """Parse a Burp "Copy to file" raw request into (method, target, headers, body)."""
    if b"\r\n\r\n" in raw:
        head, _, body = raw.partition(b"\r\n\r\n")
    elif b"\n\n" in raw:
        head, _, body = raw.partition(b"\n\n")
    else:
        head, body = raw, b""
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    request_line = lines[0].decode("latin-1").strip()
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError(f"not a valid request line: {request_line!r}")
    method, target = parts[0], parts[1]
    headers = [ln.decode("latin-1").rstrip() for ln in lines[1:] if ln.strip()]
    return method, target, headers, body


def header_value(headers, name):
    name = name.lower()
    for h in headers:
        if ":" in h and h.split(":", 1)[0].strip().lower() == name:
            return h.split(":", 1)[1].strip()
    return None


def build_request_bytes(method, target, headers, body):
    """Serialize the request, adding Host/Content-Length when missing.

    Connection: close is forced (any existing Connection header replaced) so the
    response terminates with an EOF and per-worker reads finish deterministically.
    """
    names = {h.split(":", 1)[0].strip().lower() for h in headers if ":" in h}
    if body and "content-length" not in names:
        headers = headers + [f"Content-Length: {len(body)}"]
    headers = [h for h in headers if not h.lower().startswith("connection:")]
    headers.append("Connection: close")
    head = f"{method} {target} HTTP/1.1\r\n" + "".join(h + "\r\n" for h in headers) + "\r\n"
    return head.encode("latin-1") + body


def dechunk(body):
    """Minimal chunked-transfer decoding so body lengths group consistently."""
    out, i = b"", 0
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            return out or body
        try:
            size = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            return out or body
        if size == 0:
            return out
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2


def read_response(sock):
    """Read a full response: headers, then body per Content-Length (or to EOF)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    clen = None
    chunked = False
    for line in head.split(b"\r\n")[1:]:
        low = line.lower()
        if low.startswith(b"content-length:"):
            try:
                clen = int(line.split(b":", 1)[1].strip())
            except ValueError:
                clen = None
        elif low.startswith(b"transfer-encoding:") and b"chunked" in low:
            chunked = True
    if clen is None:
        while True:
            try:
                chunk = sock.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            rest += chunk
        if chunked:
            rest = dechunk(rest)
    else:
        while len(rest) < clen:
            try:
                chunk = sock.recv(min(65536, clen - len(rest)))
            except OSError:
                break
            if not chunk:
                break
            rest += chunk
        rest = rest[:clen]
    return head + b"\r\n\r\n" + rest


def summarize(data: bytes):
    """-> (status_code_str, body_len, sha256[:12], body)"""
    if b"\r\n\r\n" in data:
        head, body = data.split(b"\r\n\r\n", 1)
    else:
        head, body = data, b""
    first = head.split(b"\r\n")[0].decode("latin-1", "replace").strip()
    parts = first.split()
    code = parts[1] if len(parts) >= 2 else "-"
    return code, len(body), hashlib.sha256(body).hexdigest()[:12], body


def fire_one(idx, method, target, headers, body, host, port, tls, insecure, timeout, barrier, results):
    sock = None
    try:
        # Substitute {{i}} in every part BEFORE serializing, so Content-Length is computed
        # on the substituted body. Building once up front and .replace()-ing the finished
        # bytes here left the auto-added Content-Length counting the 5-char literal `{{i}}`
        # instead of the value it becomes -- an over-long CL makes the server block waiting
        # for body bytes that never arrive, so every length-changing {{i}} race silently
        # timed out. Per-worker build is a handful of string ops and happens before the
        # barrier, so the last-byte sync is unaffected.
        n = str(idx)
        req = build_request_bytes(
            method,
            target.replace("{{i}}", n),
            [h.replace("{{i}}", n) for h in headers],
            body.replace(b"{{i}}", n.encode()),
        )
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if tls:
            ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(req[:-1])                    # last-byte sync: hold the final byte
        barrier.wait(timeout=timeout * 3)
        sock.sendall(req[-1:])                    # ...and release it together with everyone
        results[idx] = ("ok", summarize(read_response(sock)))
    except Exception as exc:  # per-request failure is a result, not a crash
        results[idx] = ("err", f"{type(exc).__name__}: {exc}")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(
        prog="race_harness.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("url", nargs="?", help="target URL (omit when -r is given)")
    ap.add_argument("-r", "--request", help="raw HTTP request file (Burp: right-click -> Copy to file)")
    ap.add_argument("-X", "--method", help="HTTP method (curl mode; default GET, or POST if -d)")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help="request header 'Name: value' (repeatable; appended in -r mode too)")
    ap.add_argument("-d", "--data", help="request body (curl mode)")
    ap.add_argument("-n", "--count", type=int, default=DEFAULT_COUNT,
                    help=f"number of near-simultaneous requests (default {DEFAULT_COUNT})")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="per-request connect/read timeout in seconds (default 10)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    ap.add_argument("--diff", action="store_true",
                    help="exit non-zero and flag any response outside the modal group")
    ap.add_argument("--scheme", choices=("http", "https"), default=None,
                    help="scheme for -r mode (default: https, except port 80/8080/8000 -> http)")
    args = ap.parse_args()

    if not args.request and not args.url:
        ap.error("need -r REQFILE or a URL")

    extra_headers = list(args.header)
    body = b""
    tls = False

    if args.request:
        with open(args.request, "rb") as f:
            raw = f.read()
        method, target, headers, body = parse_raw_request(raw)
        headers += extra_headers
        if target.startswith(("http://", "https://")):  # absolute-form (proxy capture)
            pu = urllib.parse.urlparse(target)
            scheme = pu.scheme
            host, port = pu.hostname, pu.port
            target = (pu.path or "/") + (f"?{pu.query}" if pu.query else "")
        else:
            host_hdr = header_value(headers, "host")
            if not host_hdr:
                ap.error("raw request has no Host header; use URL mode or add one")
            if ":" in host_hdr and not host_hdr.endswith("]"):
                hst, _, prt = host_hdr.rpartition(":")
                host = hst
                port = int(prt) if prt.isdigit() else None
            else:
                host, port = host_hdr, None
            scheme = args.scheme
            if scheme is None:
                scheme = "http" if port in (80, 8080, 8000) else "https"
        if port is None:
            port = 443 if scheme == "https" else 80
    else:
        pu = urllib.parse.urlparse(args.url)
        if pu.scheme not in ("http", "https") or not pu.hostname:
            ap.error("URL must look like https://host/path")
        scheme = pu.scheme
        host = pu.hostname
        port = pu.port or (443 if scheme == "https" else 80)
        target = (pu.path or "/") + (f"?{pu.query}" if pu.query else "")
        method = args.method or ("POST" if args.data is not None else "GET")
        headers = extra_headers
        if args.data is not None:
            body = args.data.encode()

    if not header_value(headers, "host"):
        # Include the port unless it is the scheme default -- a bare "Host: 127.0.0.1"
        # misroutes name-based vhosts on non-standard ports.
        default_port = 443 if scheme == "https" else 80
        headers = headers + [f"Host: {host if port == default_port else f'{host}:{port}'}"]

    tls = scheme == "https"

    print(f"=== race_harness: {args.count} x {method} {target} -> {host}:{port} "
          f"({scheme}, tls verify={'off' if args.insecure else 'on'}) ===")
    print("sync: thread barrier + last-byte (all but final byte sent, barrier, release)\n")

    if args.count < 2:
        print("WARNING: a race test needs -n >= 2; running anyway.\n")

    results = [None] * args.count
    barrier = threading.Barrier(max(1, args.count))
    threads = [
        threading.Thread(
            target=fire_one,
            args=(i, method, target, headers, body, host, port, tls, args.insecure,
                  args.timeout, barrier, results),
            daemon=True,
        )
        for i in range(args.count)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    groups = {}
    errors = []
    for i, res in enumerate(results):
        if res[0] == "ok":
            groups.setdefault(res[1][:3], []).append(i)
        else:
            errors.append((i, res[1]))

    if not groups:
        for i, msg in errors[:3]:
            print(f"  request #{i}: {msg}")
        print(f"\nNo responses captured ({len(errors)} transport errors) -- check target/timeout.")
        sys.exit(1)

    modal_key = max(groups, key=lambda k: len(groups[k]))

    n_ok = sum(len(v) for v in groups.values())
    print(f"{n_ok}/{args.count} responses captured"
          + (f", {len(errors)} transport errors" if errors else "") + "\n")
    print("Response groups (status / body-len / sha256[:12]):")
    for key, idxs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        marks = []
        if key == modal_key:
            marks.append("<-- modal")
        elif args.diff:
            marks.append("<-- DIVERGENT")
        print(f"  {len(idxs):>4} x  {key[0]:<4} / {key[1]:<7} / {key[2]}  {' '.join(marks)}")
    if errors:
        print(f"  {len(errors):>4} x  ERROR ({errors[0][1]})")

    divergent = [k for k in groups if k != modal_key]
    if divergent:
        if args.diff:
            print("\n!!! RACE DIVERGENCE !!!")
            for k in divergent:
                idx = groups[k][0]
                preview = results[idx][1][3][:200].decode("latin-1", "replace").replace("\n", "\\n")
                print(f"  request #{idx}: {k[0]} / {k[1]} / {k[2]}")
                print(f"    body preview: {preview!r}")
            print(f"\nModal group: {len(groups[modal_key])} x {modal_key[0]} / "
                  f"{modal_key[1]} / {modal_key[2]}")
            print("One divergent response = a different outcome landed = chase it in Burp "
                  "(repeat that single request and confirm the state change).")
            sys.exit(2)
        print("\n(note: responses diverged from the modal group -- re-run with --diff "
              "for details and a non-zero exit)")
    else:
        print("\nNo divergence observed. One clean pass does NOT disprove a race -- server")
        print("tick alignment is probabilistic; run several passes (and try larger -n) before")
        print("moving on.")


if __name__ == "__main__":
    main()
