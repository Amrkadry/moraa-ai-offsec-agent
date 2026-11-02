#!/usr/bin/env python3
"""Offline tests for scripts/race_harness.py.

stdlib unittest only. Two layers:

* Pure-function unit tests for the parsing/grouping logic that is exactly testable
  offline: Burp "Copy to file" raw-request parsing, header lookup, request
  serialization (auto Host/Content-Length, forced Connection: close), minimal chunked
  decoding, and response summarizing (status / body length / sha256[:12]).

* Integration tests against a throwaway http.server on 127.0.0.1 — never a real host.
  These drive rh.main() end-to-end over REAL localhost sockets, which is what makes the
  synchronization machinery testable at all. THE BARRIER ITSELF IS NOT DIRECTLY
  UNIT-TESTED (per the task brief): its observable contract is tested indirectly —
  every integration run pushes N workers through send-all-but-last-byte -> barrier ->
  release, and fire_one bounds its barrier wait at timeout*3, so a broken barrier
  surfaces as transport errors/timeout in these tests rather than a hang. What the
  timing precision of the last-byte sync actually buys on a live target remains a
  manual/Turbo-Intruder question and is NOT verified here.

Run:  python3 -m unittest discover -s tests -p "test_race_harness.py" -v
"""

import contextlib
import hashlib
import http.server
import io
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import race_harness as rh  # noqa: E402

COMMON_BODY = b"fixture common body"
DIVERGENT_BODY = b"fixture divergent body"


def sha12(body):
    return hashlib.sha256(body).hexdigest()[:12]


def closed_localhost_port():
    """A port on 127.0.0.1 with (almost certainly) nothing listening: bind, read the
    ephemeral port, close. Connection attempts there fail instantly and locally."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------
# raw-request parsing (Burp "Copy to file" format)
# --------------------------------------------------------------------------

class TestParseRawRequest(unittest.TestCase):

    def test_crlf_request_yields_method_target_headers_body(self):
        raw = (b"POST /api/redeem HTTP/1.1\r\n"
               b"Host: fixture-target.test\r\n"
               b"Content-Type: application/json\r\n"
               b"Cookie: s=fixture\r\n"
               b"\r\n"
               b'{"code":"XMAS"}')
        method, target, headers, body = rh.parse_raw_request(raw)
        self.assertEqual(method, "POST")
        self.assertEqual(target, "/api/redeem")
        self.assertEqual(headers, ["Host: fixture-target.test",
                                   "Content-Type: application/json",
                                   "Cookie: s=fixture"])
        self.assertEqual(body, b'{"code":"XMAS"}')

    def test_lf_only_request_still_parses(self):
        raw = b"GET /api/ping HTTP/1.1\nHost: fixture-target.test\n\n"
        method, target, headers, body = rh.parse_raw_request(raw)
        self.assertEqual((method, target, headers, body),
                         ("GET", "/api/ping", ["Host: fixture-target.test"], b""))

    def test_request_without_body_has_empty_body(self):
        method, target, headers, body = rh.parse_raw_request(
            b"GET / HTTP/1.1\r\nHost: fixture-target.test\r\n\r\n")
        self.assertEqual(body, b"")
        self.assertEqual(len(headers), 1)

    def test_absolute_form_target_is_preserved_by_the_parser(self):
        _, target, _, _ = rh.parse_raw_request(
            b"GET http://fixture-target.test/api/x?a=1 HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(target, "http://fixture-target.test/api/x?a=1")

    def test_blank_header_lines_are_dropped(self):
        _, _, headers, _ = rh.parse_raw_request(
            b"GET / HTTP/1.1\r\nHost: fixture-target.test\r\n\r\n\r\nX: y\r\n\r\n")
        self.assertNotIn("", headers)

    def test_broken_request_line_raises_valueerror(self):
        with self.assertRaises(ValueError):
            rh.parse_raw_request(b"GETHTTP/1.1\r\nHost: x\r\n\r\n")

    def test_header_value_is_case_insensitive_and_returns_first_match(self):
        headers = ["hOsT: first.test", "X-A: 1", "host: second.test"]
        self.assertEqual(rh.header_value(headers, "HOST"), "first.test")
        self.assertEqual(rh.header_value(headers, "x-a"), "1")
        self.assertIsNone(rh.header_value(headers, "x-missing"))


# --------------------------------------------------------------------------
# serialization: auto Host/Content-Length, forced Connection: close
# --------------------------------------------------------------------------

class TestBuildRequestBytes(unittest.TestCase):

    def test_body_gets_a_correct_auto_content_length(self):
        data = rh.build_request_bytes("POST", "/api/redeem", ["Host: t.test"], b"abcde")
        head, _, body = data.partition(b"\r\n\r\n")
        self.assertEqual(body, b"abcde")
        self.assertTrue(head.startswith(b"POST /api/redeem HTTP/1.1\r\n"))
        self.assertIn(b"Host: t.test\r\n", head)
        self.assertIn(b"Content-Length: 5\r\n", head)

    def test_no_body_means_no_content_length(self):
        data = rh.build_request_bytes("GET", "/", ["Host: t.test"], b"")
        self.assertNotIn(b"Content-Length:", data)

    def test_existing_content_length_is_not_duplicated(self):
        data = rh.build_request_bytes("POST", "/", ["Host: t.test",
                                                    "Content-Length: 5"], b"abcde")
        self.assertEqual(data.count(b"Content-Length:"), 1)

    def test_connection_close_is_forced_replacing_any_existing_value(self):
        data = rh.build_request_bytes("GET", "/", ["Host: t.test",
                                                   "Connection: keep-alive"], b"")
        self.assertEqual(data.count(b"Connection:"), 1)
        self.assertIn(b"Connection: close\r\n", data)

    def test_headers_and_body_are_separated_by_a_blank_line(self):
        data = rh.build_request_bytes("GET", "/", ["Host: t.test"], b"")
        self.assertTrue(data.endswith(b"\r\n\r\n"))


# --------------------------------------------------------------------------
# chunked decoding + response summarizing (the grouping key)
# --------------------------------------------------------------------------

class TestDechunkAndSummarize(unittest.TestCase):

    def test_minimal_chunked_body_is_decoded(self):
        self.assertEqual(rh.dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"), b"Wikipedia")

    def test_chunk_extensions_and_empty_input_are_tolerated(self):
        self.assertEqual(rh.dechunk(b"4;ext=1\r\nWiki\r\n0\r\n\r\n"), b"Wiki")
        self.assertEqual(rh.dechunk(b""), b"")

    def test_non_chunked_garbage_is_returned_as_is(self):
        self.assertEqual(rh.dechunk(b"not chunked at all"), b"not chunked at all")

    def test_summarize_groups_on_status_length_and_body_hash(self):
        body = COMMON_BODY
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        status, length, digest, got = rh.summarize(head + body)
        self.assertEqual(status, "200")
        self.assertEqual(length, len(COMMON_BODY))
        self.assertEqual(digest, sha12(COMMON_BODY))
        self.assertEqual(got, body)

    def test_summarize_without_headers_treats_everything_as_body(self):
        status, length, digest, got = rh.summarize(b"HTTP/1.1 404 Not Found")
        self.assertEqual(status, "404")
        self.assertEqual((length, digest, got), (0, sha12(b""), b""))


# --------------------------------------------------------------------------
# integration: real localhost sockets through rh.main()
# --------------------------------------------------------------------------

class _RaceHandler(http.server.BaseHTTPRequestHandler):
    """Answers every request with a fixed body; a configured path (diverge_at) gets a
    different one — the deterministic stand-in for the one-in-N race win."""

    protocol_version = "HTTP/1.1"
    server_version = "FixtureRace/1.0"

    def log_message(self, fmt, *args):
        pass

    def _handle(self):
        fx = self.server.fixture
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        fx.requests.append({
            "line": self.requestline,
            "path": self.path,
            "headers": self.headers,          # email Message: case-insensitive .get
            "host": self.headers.get("Host"),
            "content_length": self.headers.get("Content-Length"),
            "connection": self.headers.get("Connection"),
            "body": body,
        })
        resp = DIVERGENT_BODY if self.path == fx.diverge_at else COMMON_BODY
        fx.requests[-1]["resp"] = resp
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    do_GET = _handle
    do_POST = _handle


class _FixtureRaceServer:
    """Throwaway ThreadingHTTPServer on 127.0.0.1; one thread per connection, which is
    what lets N race-harness workers hold their last byte without deadlocking it."""

    def __init__(self, diverge_at=None):
        self.requests = []
        self.diverge_at = diverge_at
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RaceHandler)
        self.httpd.fixture = self
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def url(self, path="/api/redeem"):
        return "http://127.0.0.1:%d%s" % (self.port, path)


def run_harness(argv):
    """Drive rh.main in-process (real sockets, 127.0.0.1 only); -> (SystemExit|None,
    stdout, stderr). main() takes no argv (argparse reads sys.argv), so argv is patched."""
    out, err = io.StringIO(), io.StringIO()
    exc = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
         mock.patch("sys.argv", ["race_harness.py", *argv]):
        try:
            rh.main()
        except SystemExit as e:
            exc = e
    return exc, out.getvalue(), err.getvalue()


class TestGroupingAgainstLocalServer(unittest.TestCase):

    def test_identical_responses_form_one_modal_group_and_exit_zero(self):
        with _FixtureRaceServer() as fx:
            body = b'{"code":"XMAS"}'
            exc, out, _ = run_harness([fx.url(), "-X", "POST", "-d", body.decode(),
                                       "-n", "4", "--timeout", "5"])
            reqs = list(fx.requests)
        self.assertIsNone(exc)                       # identical responses -> exit 0
        self.assertIn("Response groups", out)
        self.assertIn("No divergence observed", out)
        self.assertNotIn("RACE DIVERGENCE", out)
        # grouping key = status / body-len / sha256[:12], marked modal
        self.assertRegex(out, r"4 x\s+200\s*/\s*%d\s*/\s*%s\s*<-- modal"
                         % (len(COMMON_BODY), sha12(COMMON_BODY)))
        # all 4 landed, with the auto-filled headers correct. The auto-filled Host carries
        # the non-default fixture port so name-based vhosts route correctly.
        self.assertEqual(len(reqs), 4)
        for r in reqs:
            self.assertEqual(r["path"], "/api/redeem")
            self.assertEqual(r["host"], "127.0.0.1:%d" % fx.port)      # Host auto-filled (with port)
            self.assertEqual(r["content_length"], str(len(body)))      # CL auto-filled
            self.assertEqual(r["body"], body)
            self.assertEqual(r["connection"], "close")                 # forced, no proxy reuse

    def test_one_divergent_response_is_flagged_by_diff_and_exits_2(self):
        with _FixtureRaceServer(diverge_at="/api/2") as fx:
            exc, out, _ = run_harness([fx.url("/api/{{i}}"), "-n", "4",
                                       "--diff", "--timeout", "5"])
            paths = [r["path"] for r in fx.requests]
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 2)
        self.assertIn("RACE DIVERGENCE", out)
        self.assertIn("DIVERGENT", out)
        self.assertIn(repr(DIVERGENT_BODY.decode("latin-1", "replace").replace("\n", "\\n")),
                      out)                     # body preview of the divergent response
        # 3x modal + 1x divergent, and --diff told the user to chase it
        self.assertRegex(out, r"3 x\s+200\s*/\s*%d\s*/\s*%s\s*<-- modal"
                         % (len(COMMON_BODY), sha12(COMMON_BODY)))
        self.assertIn("chase it in Burp", out)
        self.assertEqual(paths.count("/api/2"), 1)   # the divergence came from that worker

    def test_divergence_without_diff_notes_but_exits_zero(self):
        with _FixtureRaceServer(diverge_at="/api/2") as fx:
            exc, out, _ = run_harness([fx.url("/api/{{i}}"), "-n", "4", "--timeout", "5"])
        self.assertIsNone(exc)
        self.assertNotIn("RACE DIVERGENCE", out)
        self.assertIn("re-run with --diff", out)

    def test_index_template_substitutes_a_distinct_value_per_worker(self):
        with _FixtureRaceServer() as fx:
            exc, out, _ = run_harness([fx.url("/api/{{i}}"), "-n", "4", "--timeout", "5"])
            reqs = sorted(fx.requests, key=lambda r: r["path"])
        self.assertIsNone(exc)
        # each worker sent its own index — 4 distinct paths, no duplicates
        self.assertEqual([r["path"] for r in reqs],
                         ["/api/0", "/api/1", "/api/2", "/api/3"])
        # all responses were identical, so the run is still one clean modal group
        self.assertEqual({r["resp"] for r in reqs}, {COMMON_BODY})
        self.assertIn("No divergence observed", out)

    def test_transport_errors_are_reported_and_exit_1(self):
        port = closed_localhost_port()
        with tempfile.TemporaryDirectory() as td:
            req = Path(td) / "req.txt"
            req.write_bytes(b"POST /api/redeem HTTP/1.1\r\n"
                            b"Host: 127.0.0.1:%d\r\n"
                            b"Content-Type: application/json\r\n"
                            b"\r\n" % port)
            exc, out, _ = run_harness(["-r", str(req), "-n", "2", "--timeout", "2"])
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 1)
        self.assertIn("No responses captured", out)
        self.assertIn("2 transport errors", out)


class TestRawRequestModeParsing(unittest.TestCase):
    """Host/port/scheme derivation from the -r file, asserted on the banner main()
    prints BEFORE firing (so these never depend on a connection succeeding)."""

    def rawfile(self, td, raw):
        f = Path(td) / "req.txt"
        f.write_bytes(raw)
        return str(f)

    def test_port_8080_defaults_to_http(self):
        # 8080 is in the script's explicit http set, so scheme must derive as http. Nothing
        # is expected to listen on 127.0.0.1:8080; whatever happens after the banner (exit 0
        # if something local answers, exit 1 on refusal), only the banner is asserted.
        with tempfile.TemporaryDirectory() as td:
            req = self.rawfile(td, b"POST /api/redeem HTTP/1.1\r\n"
                                   b"Host: 127.0.0.1:8080\r\n\r\n")
            exc, out, _ = run_harness(["-r", req, "-n", "2", "--timeout", "2"])
        self.assertIn("POST /api/redeem -> 127.0.0.1:8080 (http, tls verify=on)", out)
        self.assertTrue(exc is None or exc.code == 1, "unexpected exit: %r" % (exc,))

    def test_other_ports_default_to_https(self):
        port = closed_localhost_port()
        with tempfile.TemporaryDirectory() as td:
            req = self.rawfile(td, b"POST /api/redeem HTTP/1.1\r\n"
                                   b"Host: 127.0.0.1:%d\r\n\r\n" % port)
            exc, out, _ = run_harness(["-r", req, "-n", "2", "--timeout", "2"])
        # TLS never gets attempted: connect() is refused locally first
        self.assertIn("POST /api/redeem -> 127.0.0.1:%d (https, tls verify=on)" % port, out)
        self.assertEqual(exc.code, 1)
        self.assertIn("No responses captured", out)

    def test_absolute_form_target_sets_host_port_and_strips_the_target(self):
        port = closed_localhost_port()
        with tempfile.TemporaryDirectory() as td:
            req = self.rawfile(td, b"GET http://127.0.0.1:%d/api/x?a=1 HTTP/1.1\r\n"
                                   b"Host: 127.0.0.1:%d\r\n\r\n" % (port, port))
            exc, out, _ = run_harness(["-r", req, "-n", "2", "--timeout", "2"])
        self.assertIn("GET /api/x?a=1 -> 127.0.0.1:%d (http, tls verify=on)" % port, out)
        self.assertEqual(exc.code, 1)

    def test_raw_request_without_host_header_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as td:
            req = self.rawfile(td, b"GET /api/x HTTP/1.1\r\nX-Other: 1\r\n\r\n")
            exc, _, err = run_harness(["-r", req, "-n", "2", "--timeout", "2"])
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 2)
        self.assertIn("no Host header", err)

    def test_url_mode_auto_fills_host_and_content_length_on_the_wire(self):
        with _FixtureRaceServer() as fx:
            body = '{"code":"XMAS"}'
            exc, out, _ = run_harness([fx.url(), "-X", "POST", "-d", body,
                                       "-H", "X-Fixture: 1", "-n", "3", "--timeout", "5"])
            reqs = list(fx.requests)
            port = fx.port
        self.assertIsNone(exc)
        self.assertEqual(len(reqs), 3)
        for r in reqs:
            # auto-filled Host carries the (non-default) fixture port -- bare "127.0.0.1"
            # would misroute a name-based vhost on a non-standard port.
            self.assertEqual(r["host"], "127.0.0.1:%d" % port)
            self.assertEqual(r["content_length"], str(len(body)))
            self.assertEqual(r["body"], body.encode())
            self.assertEqual(r["headers"].get("X-Fixture"), "1")

    def test_length_changing_body_template_gets_a_correct_per_worker_content_length(self):
        # {{i}} (5 chars) becomes str(idx) (1+ chars): the body length differs per worker.
        # Content-Length must be recomputed AFTER substitution or the server blocks on body
        # bytes that never come. Regression guard for the CL-vs-{{i}} bug: assert every
        # worker's declared CL equals the actual received body length AND its own idx.
        with _FixtureRaceServer() as fx:
            exc, out, _ = run_harness([fx.url(), "-X", "POST",
                                       "-d", '{"code":"{{i}}"}',
                                       "-n", "12", "--timeout", "5"])
            reqs = list(fx.requests)
        self.assertIsNone(exc)
        self.assertEqual(len(reqs), 12)                 # none timed out on a wrong CL
        seen = set()
        for r in reqs:
            self.assertEqual(r["content_length"], str(len(r["body"])))
            self.assertRegex(r["body"], rb'^\{"code":"\d+"\}$')
            idx = r["body"].split(b'"')[3]              # the substituted value
            seen.add(idx)
        self.assertEqual(len(seen), 12)                 # every worker got a distinct idx


class TestCLIContract(unittest.TestCase):

    def test_neither_url_nor_request_file_is_a_usage_error(self):
        exc, _, err = run_harness([])
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 2)
        self.assertIn("need -r REQFILE or a URL", err)

    def test_banner_states_target_and_sync_mode(self):
        port = closed_localhost_port()
        exc, out, _ = run_harness(["http://127.0.0.1:%d/api/redeem" % port,
                                   "-n", "2", "--timeout", "2"])
        self.assertIn("=== race_harness: 2 x GET /api/redeem -> 127.0.0.1:%d" % port, out)
        self.assertIn("thread barrier + last-byte", out)
        self.assertEqual(exc.code, 1)      # refused locally: banner is what is asserted


if __name__ == "__main__":
    unittest.main()
