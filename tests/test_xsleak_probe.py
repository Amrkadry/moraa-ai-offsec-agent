#!/usr/bin/env python3
"""Offline tests for scripts/xsleak_probe.py.

stdlib unittest + unittest.mock only. No real network calls: HTTP is mocked at the module's
single network seam, sample_once — the same testability pattern test_cors_check.py /
test_cms_detect.py use for http_probe/probe_http. Timing never comes from a clock: every
test injects deterministic per-call samples, so the statistical gate (median +- MAD noise
floor, >=90% distinguisher consistency) is exercised with synthetic distributions that
either clear or sit inside it by construction.

The secret-redaction test is a regression test for the live incident that motivated this
file: xsleak_probe used to print the full `Cookie` header — live session JWTs — to stdout,
and this output routinely gets pasted into findings files. The negative assertions here
are explicit: the secret substring must appear NOWHERE in the output.

Run:  python3 -m unittest discover -s tests -p "test_xsleak_probe.py" -v
"""

import contextlib
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import xsleak_probe as xsp  # noqa: E402

# fixture endpoint (.test TLD, RFC 6761 reserved — never resolved, the seam is mocked)
URL = "https://fixture-x.test/api/notifications"

# a live-looking session JWT for the redaction test. Fixture value, but treated as a
# real secret: if any part of it reaches stdout, the test fails.
SECRET = "VENDOR_SSO_AUTH=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2VjcmV0LXNpZ25hdHVyZQ"


def make_sample(ms=10.0, code=200, loc="", length=100):
    """A sample_once() result dict, matching the script's own shape."""
    return {
        "ms": ms,
        "code": code,
        "class": "%dxx" % (code // 100),
        "final": URL,
        "loc": loc,
        "len": length,
    }


class ScriptedSampler:
    """Standalone-in for sample_once, routed by which leg the call belongs to (the authed
    leg is the one carrying headers — so a test that needs the legs to differ MUST pass
    -H; with no authed header the script itself sends two identical legs). Each leg gets
    a function f(k) -> sample dict, where k is the 0-based call index FOR THAT LEG (k=0 is
    the leg's warmup request; the k>=1 calls are the counted samples). A function
    returning None simulates a transport error for that call. Every call is recorded as
    "u"/"a" in .buckets, in order."""

    def __init__(self, unauth_fn=None, auth_fn=None):
        self.unauth_fn = unauth_fn or (lambda k: make_sample())
        self.auth_fn = auth_fn or (lambda k: make_sample())
        self.buckets = []

    def __call__(self, opener, url, method, headers, timeout):
        if headers:
            self.buckets.append("a")
            res = self.auth_fn(len([b for b in self.buckets if b == "a"]) - 1)
        else:
            self.buckets.append("u")
            res = self.unauth_fn(len([b for b in self.buckets if b == "u"]) - 1)
        if res is None:
            return None, "FixtureError: fixture transport failure"
        return res, None


def run_probe(argv, sampler):
    """Run xsleak_probe.main with the seam mocked; return (SystemExit-or-None, stdout).
    main() takes no argv (argparse reads sys.argv), so argv is patched in."""
    out = io.StringIO()
    exc = None
    with mock.patch.object(xsp, "sample_once", sampler), \
         mock.patch("sys.argv", ["xsleak_probe.py", *argv]), \
         contextlib.redirect_stdout(out):
        try:
            xsp.main()
        except SystemExit as e:
            exc = e
    return exc, out.getvalue()


def default_argv(*extra):
    # every scenario passes an authed header (the tool's real usage): it is the only thing
    # distinguishing the two legs on the wire, so the sampler routes on it too
    return ["-e", URL, "-n", "10", "-H", "Cookie: fixture=leg", *extra]


# --------------------------------------------------------------------------
# (1) secret redaction — the regression test for the live JWT leak
# --------------------------------------------------------------------------

class TestSecretRedaction(unittest.TestCase):

    def test_authed_header_value_never_printed(self):
        exc, out = run_probe(default_argv("-H", "Cookie: " + SECRET), ScriptedSampler())
        self.assertIsNone(exc)                       # clean run, exit code 0
        # header NAME survives redaction, value does not
        self.assertIn("Cookie", out)
        self.assertIn("<redacted", out)
        self.assertIn("%d chars" % len(SECRET), out)
        # deterministic fingerprint, not the value: sha256 prefix of the secret
        self.assertIn(hashlib.sha256(SECRET.encode()).hexdigest()[:8], out)
        # THE negative assertions — assert them explicitly, this is the whole point
        self.assertNotIn(SECRET, out)
        self.assertNotIn("VENDOR_SSO_AUTH", out)
        self.assertNotIn("c2VjcmV0LXNpZ25hdHVyZQ", out)   # even a fragment of the value
        self.assertNotIn("Traceback", out)

    def test_no_headers_at_all_prints_the_both_legs_identical_hint(self):
        exc, out = run_probe(["-e", URL, "-n", "5"], ScriptedSampler())
        self.assertIsNone(exc)
        self.assertIn("(none -- both legs identical", out)


# --------------------------------------------------------------------------
# (2) the statistical timing gate — deterministic injected distributions
# --------------------------------------------------------------------------

class TestTimingGate(unittest.TestCase):

    def test_large_separation_low_variance_is_flagged_and_exits_2(self):
        # unauth ~10ms, authed ~100ms, tiny alternating jitter (MAD ~0.05ms):
        # delta 90ms against a ~0.1ms noise floor clears both gates
        sampler = ScriptedSampler(
            unauth_fn=lambda k: make_sample(ms=10.0 + (0.1 if k % 2 else 0.0)),
            auth_fn=lambda k: make_sample(ms=100.0 + (0.1 if k % 2 else 0.0)))
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 2)                # non-zero exit on a flagged oracle
        self.assertIn("[ORACLE]", out)
        self.assertIn("timing oracle", out)
        self.assertIn("verdict: timing oracle", out)

    def test_small_delta_inside_the_noise_floor_is_clean_and_exits_0(self):
        # both legs alternate 10/30 vs 14/34: medians differ by only 4ms while each
        # leg's own spread is ~15ms MAD — below --min-ms 25 AND the 3-sigma floor
        sampler = ScriptedSampler(
            unauth_fn=lambda k: make_sample(ms=10.0 + (20.0 if k % 2 else 0.0)),
            auth_fn=lambda k: make_sample(ms=14.0 + (20.0 if k % 2 else 0.0)))
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsNone(exc)                       # zero exit when clean
        self.assertIn("[  clean]", out)
        self.assertIn("verdict: no oracle", out)
        self.assertNotIn("[ORACLE]", out)


# --------------------------------------------------------------------------
# (3) the error-vs-success distinguishers: consistent flags, inconsistent ignored
# --------------------------------------------------------------------------

class TestDistinguishers(unittest.TestCase):

    def test_consistent_status_class_difference_is_flagged(self):
        sampler = ScriptedSampler(unauth_fn=lambda k: make_sample(code=403),
                                  auth_fn=lambda k: make_sample(code=200))
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 2)
        self.assertIn("error-vs-success oracle (4xx vs 2xx)", out)

    def test_inconsistent_status_classes_are_ignored(self):
        # unauth alternates 403/200 -> modal consistency 50% < the 90% gate
        sampler = ScriptedSampler(
            unauth_fn=lambda k: make_sample(code=403 if k % 2 else 200),
            auth_fn=lambda k: make_sample(code=200))
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsNone(exc)
        self.assertIn("verdict: no oracle", out)
        self.assertNotIn("error-vs-success oracle", out)

    def test_consistent_redirect_difference_is_flagged(self):
        # same status class on both legs so ONLY the redirect distinguisher can fire
        sampler = ScriptedSampler(unauth_fn=lambda k: make_sample(code=302, loc="/login"),
                                  auth_fn=lambda k: make_sample(code=302, loc=""))
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 2)
        self.assertIn("redirect oracle", out)
        self.assertIn("'/login'", out)

    def test_inconsistent_redirects_are_ignored(self):
        sampler = ScriptedSampler(
            unauth_fn=lambda k: make_sample(code=302, loc="/login" if k % 2 else ""),
            auth_fn=lambda k: make_sample(code=302, loc=""))
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsNone(exc)
        self.assertIn("verdict: no oracle", out)
        self.assertNotIn("redirect oracle", out)

    def test_consistent_content_length_difference_is_flagged(self):
        sampler = ScriptedSampler(unauth_fn=lambda k: make_sample(length=100),
                                  auth_fn=lambda k: make_sample(length=200))
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 2)
        self.assertIn("content-length oracle (100 vs 200 bytes)", out)


# --------------------------------------------------------------------------
# (4) degraded sampling: too few valid samples -> ERROR line, never a verdict/crash
# --------------------------------------------------------------------------

class TestInsufficientSamples(unittest.TestCase):

    def test_all_authed_requests_failing_gives_error_line_and_no_verdict(self):
        sampler = ScriptedSampler(auth_fn=lambda k: None)   # every authed call errors
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsNone(exc)                              # degrades, does not exit non-zero
        self.assertIn("[ ERROR ]", out)
        self.assertIn("insufficient samples", out)
        self.assertIn("authed=0", out)
        self.assertNotIn("verdict:", out)
        self.assertNotIn("Traceback", out)

    def test_fewer_than_five_valid_samples_per_leg_is_an_error(self):
        # authed calls 0..6 error (incl. warmup), 7..10 succeed -> 4 valid samples < 5
        sampler = ScriptedSampler(auth_fn=lambda k: make_sample() if k >= 7 else None)
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsNone(exc)
        self.assertIn("[ ERROR ]", out)
        self.assertIn("authed=4", out)
        self.assertNotIn("verdict:", out)
        self.assertNotIn("Traceback", out)

    def test_unauth_leg_shortfall_is_caught_too(self):
        sampler = ScriptedSampler(unauth_fn=lambda k: None)
        exc, out = run_probe(default_argv(), sampler)
        self.assertIsNone(exc)
        self.assertIn("[ ERROR ]", out)
        self.assertIn("unauth=0", out)
        self.assertNotIn("Traceback", out)


# --------------------------------------------------------------------------
# (5) CLI contract: endpoint files, header parsing, usage errors
# --------------------------------------------------------------------------

class TestCLIContract(unittest.TestCase):

    def test_endpoints_file_is_read_with_comments_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            ef = Path(td) / "endpoints.txt"
            ef.write_text("https://fixture-a.test/a\n"
                          "# comment line\n"
                          "\n"
                          "https://fixture-b.test/b\n", encoding="utf-8")
            sampler = ScriptedSampler()
            exc, out = run_probe(["-E", str(ef), "-n", "5",
                                  "-H", "Cookie: fixture=leg"], sampler)
            self.assertIsNone(exc)
            self.assertIn("[  clean] https://fixture-a.test/a", out)
            self.assertIn("[  clean] https://fixture-b.test/b", out)
            # 2 endpoints x 2 legs x (1 warmup + 5 samples) = 24 seam calls, and every
            # sampling iteration pairs unauth before authed
            self.assertEqual(len(sampler.buckets), 24)
            self.assertEqual("".join(sampler.buckets), "ua" * 12)

    def test_malformed_header_is_a_usage_error(self):
        exc, _ = run_probe(default_argv("-H", "no-colon-here"), ScriptedSampler())
        self.assertEqual(exc.code, 2)                # run_probe captures the SystemExit

    def test_no_endpoints_is_a_usage_error(self):
        exc, _ = run_probe([], ScriptedSampler())
        self.assertEqual(exc.code, 2)


if __name__ == "__main__":
    unittest.main()
