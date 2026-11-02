#!/usr/bin/env python3
"""Offline tests for scripts/js_recon.py (TASK-008).

stdlib unittest + unittest.mock only. No real network calls: HTTP is mocked at the module's
single network seam, http_fetch — the same testability pattern test_subdomain_takeover.py /
test_cms_detect.py use. Pipeline logic (range-parallel reassembly, the TRUNCATED_DOWNLOAD
error state, single-GET fallback, sourcemap parse-confirmation, per-bundle fault isolation),
the js-analysis.md regex set, and the JSON output contract are all tested offline; live
smoke runs (code.jquery.com / .invalid) are a separate verification step, not part of the
suite.

Run:  python3 -m unittest discover -s tests -p "test_js_recon.py" -v
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import js_recon as jr  # noqa: E402

JS_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "js"

SMALL_URL = "https://fixtures-cdn.example.invalid/js/small_bundle.js"
CLEAN_URL = "https://fixtures-cdn.example.invalid/js/clean_bundle.js"
DEAD_URL = "https://dead-host.example.invalid/js/app.js"
BIG_URL = "https://fixtures-cdn.example.invalid/js/index-BigAb12Cd.js"

def _expand_fixture_markers(body):
    """Rebuild the provider-shaped secret values the fixture stores as markers.

    small_bundle.js deliberately does NOT contain full-shape credential strings:
    hosted secret scanners (GitHub push protection) reject a push that carries
    one, even an obviously synthetic one. The fixture keeps "<prefix>@@FIXTURE@@"
    markers; the detectors under test need the real shape, so expand them here.
    Replacement lengths are chosen to satisfy js_recon.SECRET_PATTERNS.
    """
    for marker, value in (
        (b"sk_live_@@FIXTURE@@", b"sk_live_" + b"E" * 24),
        (b"rk_live_@@FIXTURE@@", b"rk_live_" + b"E" * 24),
        (b"xoxb-@@FIXTURE@@",    b"xoxb-" + b"E" * 12 + b"-" + b"A" * 12),
        (b"glpat-@@FIXTURE@@",   b"glpat-" + b"E" * 20),
        (b"ghp_@@FIXTURE@@",     b"ghp_" + b"E" * 36),
        (b"ya29.@@FIXTURE@@",    b"ya29." + b"E" * 32),
    ):
        body = body.replace(marker, value)
    assert b"@@FIXTURE@@" not in body, "unexpanded fixture marker"
    return body


SMALL_BODY = _expand_fixture_markers(
    (JS_FIXTURES / "small_bundle.js").read_bytes())
CLEAN_BODY = (JS_FIXTURES / "clean_bundle.js").read_bytes()
VALID_MAP_BODY = (JS_FIXTURES / "valid_source_map.json").read_bytes()
HTML_ERROR_BODY = b"<html><head><title>404 Not Found</title></head><body>Object Not Found</body></html>"
_UNSET = object()  # add_bundle sentinel: cl unset -> default to len(body); cl=None -> no header

BIG_LEN = 3 * 1024 * 1024  # 3MB — above the default 2MB chunk threshold
CHUNK_LEN = -(-BIG_LEN // jr.DEFAULT_RANGE_CHUNKS)  # ceil division, same math as the script


def big_body() -> bytes:
    """3MB filler with obviously-synthetic markers placed mid-bundle and near the END of
    the last chunk — finding both proves chunks were reassembled in the right order."""
    buf = bytearray(b"A" * BIG_LEN)
    mid = b"ghp_" + b"E" * 36
    end = b"AKIAIOSFODNN7EXAMPLE"
    buf[len(buf) // 2:len(buf) // 2 + len(mid)] = mid
    buf[BIG_LEN - 50:BIG_LEN - 50 + len(end)] = end
    return bytes(buf)


def _resp(url, status, body, headers):
    return {"url": url, "final_url": url, "status": status,
            "headers": {k.lower(): v for k, v in headers.items()},
            "body": body, "over_cap": False, "error": None, "redirects": []}


def _err(url, message):
    return {"url": url, "final_url": url, "status": None, "headers": {}, "body": None,
            "over_cap": False, "error": message, "redirects": []}


class FakeHttp:
    """Standalone-in for http_fetch. Serves configured bundles (HEAD + ranged/plain GET),
    .map responses, and transport failures. Range semantics mirror a well-behaved origin:
    'bytes=S-E' -> 206 with exactly body[S:E+1] (unless short_chunks simulates a
    truncating/throttling origin, or ignore_range makes the server answer 200 with the
    whole file). Every call is recorded for assertions."""

    def __init__(self):
        self.bundles = {}
        self.maps = {}
        self.error_urls = set()
        self.calls = []

    def add_bundle(self, url, body, cl=_UNSET, ar=True, head_status=200, head_error=False,
                   ignore_range=False, short_chunks=None, get_slice=None):
        self.bundles[url] = {"body": body, "cl": len(body) if cl is _UNSET else cl,
                             "ar": ar, "head_status": head_status, "head_error": head_error,
                             "ignore_range": ignore_range, "short_chunks": short_chunks or {},
                             "get_slice": get_slice}

    def add_map(self, url, status, body):
        self.maps[url] = (status, body)

    def http_fetch(self, url, timeout, method="GET", extra_headers=None, max_bytes=None):
        extra = extra_headers or {}
        rng = next((v for k, v in extra.items() if k.lower() == "range"), None)
        self.calls.append({"method": method, "url": url, "range": rng})
        if url in self.error_urls:
            return _err(url, "URLError: <urlopen error fixture: name resolution failed>")
        if method == "HEAD":
            b = self.bundles.get(url)
            if b is None:
                return _resp(url, 404, b"", {})
            if b["head_error"]:
                return _err(url, "URLError: <urlopen error fixture: HEAD refused>")
            headers = {}
            if b["cl"] is not None:
                headers["content-length"] = str(b["cl"])
            if b["ar"] is True:
                headers["accept-ranges"] = "bytes"
            elif b["ar"] is False:
                headers["accept-ranges"] = "none"
            return _resp(url, b["head_status"], b"", headers)
        if url in self.maps:
            status, body = self.maps[url]
            return _resp(url, status, body, {"content-length": str(len(body))})
        b = self.bundles.get(url)
        if b is None:
            return _resp(url, 404, b"not found", {})
        if rng is not None:
            s, e = (int(x) for x in rng.split("bytes=")[1].split("-"))
            if b["ignore_range"]:
                return _resp(url, 200, b["body"], {"content-length": str(len(b["body"]))})
            chunk = b["body"][s:e + 1]
            short = b["short_chunks"].get(s)
            if short is not None:
                chunk = chunk[:short]
            return _resp(url, 206, chunk,
                         {"content-range": "bytes %d-%d/%d" % (s, e, len(b["body"]))})
        full = b["body"]
        if b["get_slice"] is not None:
            full = full[:b["get_slice"]]
        headers = {} if b["cl"] is None else {"content-length": str(b["cl"])}
        return _resp(url, 200, full, headers)

    def range_calls(self, url):
        return [c for c in self.calls if c["url"] == url and c["range"] is not None]


def scan(fake, urls, **kwargs):
    with mock.patch.object(jr, "http_fetch", fake.http_fetch):
        return jr.scan_urls(urls, **kwargs)


def default_small(fake):
    fake.add_bundle(SMALL_URL, SMALL_BODY)


class TestSmallBundleSingleGet(unittest.TestCase):
    """(1) small bundle, single-GET path: every js-analysis.md §2/§3 category extracted."""

    def setUp(self):
        self.fake = FakeHttp()
        default_small(self.fake)
        self.res = scan(self.fake, [SMALL_URL])

    def test_single_get_path_taken_and_size_asserted(self):
        b = self.res["metadata"]["bundles"][0]
        self.assertEqual(b["status"], "ok")
        self.assertEqual(b["download"], "single-GET")
        self.assertFalse(b["truncated"])
        self.assertEqual(b["size"], len(SMALL_BODY))
        self.assertEqual(b["content_length"], len(SMALL_BODY))
        self.assertEqual(len(self.fake.calls), 3)  # HEAD + one GET + the <url>.map probe
        self.assertEqual([c["method"] for c in self.fake.calls], ["HEAD", "GET", "GET"])
        self.assertEqual(self.fake.calls[2]["url"], SMALL_URL + ".map")

    def test_every_secret_category_detected(self):
        kinds = {f["kind"] for f in self.res["findings"] if f["type"] == "js_secret"}
        expected = {kind for kind, _, _, _ in jr.SECRET_PATTERNS}
        self.assertEqual(kinds, expected)

    def test_line_numbers_recorded(self):
        aws = next(f for f in self.res["findings"]
                   if f["type"] == "js_secret" and f["kind"] == "aws_access_key_id")
        # derive the expected line from the fixture rather than hardcoding it, so
        # editing the fixture header cannot silently break this test
        expected_line = next(
            n for n, l in enumerate(SMALL_BODY.decode().splitlines(), 1)
            if b"AKIAIOSFODNN7EXAMPLE".decode() in l and "awsKeyId" in l)
        self.assertEqual(aws["line"], expected_line)
        self.assertTrue(any("line %d" % expected_line in e for e in aws["evidence"]))
        self.assertIn("AKIAIOSFODNN7EXAMPLE", " ".join(aws["evidence"]))

    def test_severity_ladder_by_confidence_tier(self):
        by_kind = {f["kind"]: f for f in self.res["findings"] if f["type"] == "js_secret"}
        self.assertEqual(by_kind["stripe_secret_key"]["severity"], "medium")  # high tier
        self.assertEqual(by_kind["stripe_secret_key"]["confidence"], 0.70)
        self.assertEqual(by_kind["aws_access_key_id"]["severity"], "low")    # medium tier
        self.assertEqual(by_kind["aws_access_key_id"]["confidence"], 0.50)
        self.assertEqual(by_kind["google_api_key"]["severity"], "info")      # low tier
        self.assertEqual(by_kind["google_api_key"]["confidence"], 0.30)
        for f in self.res["findings"]:
            self.assertNotIn(f["severity"], ("high", "critical"))  # never from a regex alone
        sk = by_kind["stripe_secret_key"]
        self.assertIn("NOT verified live", " ".join(sk["evidence"]))
        self.assertIn("validate.md", sk["next_action"])

    def test_hosts_endpoints_routes_config_summary(self):
        summary = next(f for f in self.res["findings"] if f["type"] == "js_endpoint_summary")
        self.assertEqual(summary["severity"], "info")
        self.assertIn("https://cdn.fixture-example.invalid:8443", summary["hosts"])
        for ep in ("/api/v2/users", "/internal/health", "/oauth/token", "/v1/accounts/9"):
            self.assertIn(ep, summary["endpoints"])
        self.assertIn("/admin/settings", summary["spa_routes"])
        self.assertIn("/dashboard", summary["spa_routes"])
        self.assertTrue(any(v.startswith("__ENV__") for v in summary["runtime_config"]))
        self.assertTrue(any(v.startswith("window.__CONFIG__") for v in summary["runtime_config"]))
        self.assertIn("VITE_API_BASE", " ".join(summary["runtime_config"]))
        self.assertIn("authz + IDOR", summary["next_action"])


class TestLargeBundleRangeParallel(unittest.TestCase):
    """(2) large bundle + Accept-Ranges -> range-parallel path, chunks reassembled in
    order (markers placed mid-bundle and in the final chunk prove ordering)."""

    def setUp(self):
        self.fake = FakeHttp()
        self.fake.add_bundle(BIG_URL, big_body())  # defaults: cl=len, accept-ranges: bytes
        self.res = scan(self.fake, [BIG_URL])

    def test_range_parallel_path_taken(self):
        b = self.res["metadata"]["bundles"][0]
        self.assertEqual(b["status"], "ok")
        self.assertTrue(b["download"].startswith("range-parallel ("))
        self.assertTrue(b["accept_ranges"])
        self.assertFalse(b["truncated"])
        self.assertEqual(b["size"], BIG_LEN)

    def test_all_chunks_requested_with_correct_ranges(self):
        rc = sorted(self.fake.range_calls(BIG_URL),
                    key=lambda c: int(c["range"].split("bytes=")[1].split("-")[0]))
        self.assertEqual(len(rc), jr.DEFAULT_RANGE_CHUNKS)
        self.assertEqual(rc[0]["range"], "bytes=0-%d" % (CHUNK_LEN - 1))
        last_start = (jr.DEFAULT_RANGE_CHUNKS - 1) * CHUNK_LEN
        self.assertEqual(rc[-1]["range"], "bytes=%d-%d" % (last_start, BIG_LEN - 1))

    def test_reassembly_is_ordered_and_complete(self):
        kinds = {f["kind"] for f in self.res["findings"] if f["type"] == "js_secret"}
        self.assertEqual(kinds, {"github_token", "aws_access_key_id"})
        gh = next(f for f in self.res["findings"]
                  if f["type"] == "js_secret" and f["kind"] == "github_token")
        # the mid-bundle marker survived intact -> chunk order preserved (a misordered
        # or partial join would truncate/corrupt the 40-char token)
        self.assertEqual(gh["evidence"][1], "matched: %s" % ("ghp_" + "E" * 36))
        aws = next(f for f in self.res["findings"]
                   if f["type"] == "js_secret" and f["kind"] == "aws_access_key_id")
        self.assertEqual(aws["evidence"][1], "matched: AKIAIOSFODNN7EXAMPLE")  # end-of-file marker


class TestTruncatedDownload(unittest.TestCase):
    """(3) THE critical lesson from js-analysis.md §1: a short pull is a distinct
    TRUNCATED_DOWNLOAD error state — the partial bytes are NEVER mined as if complete."""

    def test_short_range_chunk_is_truncated_not_mined(self):
        fake = FakeHttp()
        # last chunk (bytes=2000-2999) delivers only 200 of its 1000 bytes
        body = b"B" * 50 + b"AKIAIOSFODNN7EXAMPLE" + b"B" * (3000 - 70)
        fake.add_bundle(SMALL_URL, body, cl=3000, ar=True, short_chunks={2000: 200})
        res = scan(fake, [SMALL_URL], range_chunks=3, chunk_threshold_mb=0)
        b = res["metadata"]["bundles"][0]
        self.assertEqual(b["status"], "truncated")
        self.assertTrue(b["truncated"])
        # chunks are all-or-nothing: the short chunk retried and stayed failed, so only
        # the two complete chunks' bytes count toward the received total
        self.assertEqual(b["size"], 2000)
        self.assertTrue(res["errors"])
        joined = " ".join(res["errors"])
        self.assertIn("TRUNCATED_DOWNLOAD", joined)
        self.assertIn("2000 of 3000", joined)
        # the AKIA key IS inside the received bytes (chunk 0) — must still NOT be reported:
        self.assertEqual([f for f in res["findings"] if f["type"] == "js_secret"], [])
        self.assertEqual([f for f in res["findings"] if f["type"] == "js_endpoint_summary"], [])
        self.assertIn("Bundle NOT mined", joined)  # "a short pull is a false-negative factory"
        # the failing chunk was retried (CHUNK_RETRIES + 1 attempts) before giving up
        last_chunk_calls = [c for c in fake.range_calls(SMALL_URL)
                            if c["range"] == "bytes=2000-2999"]
        self.assertEqual(len(last_chunk_calls), jr.CHUNK_RETRIES + 1)

    def test_short_single_get_is_truncated_not_mined(self):
        fake = FakeHttp()
        # the NMS-appliance single-stream failure, replayed: Content-Length says 1000, origin RSTs at 600
        body = b"C" * 100 + b"AKIAIOSFODNN7EXAMPLE" + b"C" * (1000 - 120)
        fake.add_bundle(SMALL_URL, body, cl=1000, ar=False, get_slice=600)
        res = scan(fake, [SMALL_URL])
        b = res["metadata"]["bundles"][0]
        self.assertEqual(b["download"], "single-GET")
        self.assertEqual(b["status"], "truncated")
        self.assertEqual(b["size"], 600)
        self.assertIn("TRUNCATED_DOWNLOAD", " ".join(res["errors"]))
        self.assertIn("600", " ".join(res["errors"]))
        self.assertIn("1000", " ".join(res["errors"]))
        self.assertEqual([f for f in res["findings"] if f["type"] == "js_secret"], [])


class TestNoRangeSupportFallback(unittest.TestCase):
    """(4) large bundle WITHOUT range support -> clean single-GET fallback."""

    def test_accept_ranges_none_falls_back_to_single_get(self):
        fake = FakeHttp()
        fake.add_bundle(BIG_URL, big_body(), ar=False)
        res = scan(fake, [BIG_URL])
        b = res["metadata"]["bundles"][0]
        self.assertEqual(b["status"], "ok")
        self.assertEqual(b["download"], "single-GET")
        self.assertIs(b["accept_ranges"], False)
        self.assertEqual(b["size"], BIG_LEN)
        kinds = {f["kind"] for f in res["findings"] if f["type"] == "js_secret"}
        self.assertEqual(kinds, {"github_token", "aws_access_key_id"})
        self.assertFalse(any(c["range"] for c in fake.calls))

    def test_head_rejected_falls_back_to_ranged_probe_and_range_path(self):
        fake = FakeHttp()
        fake.add_bundle(BIG_URL, big_body(), head_status=405)  # HEAD-hostile CDN
        res = scan(fake, [BIG_URL])
        b = res["metadata"]["bundles"][0]
        self.assertEqual(b["status"], "ok")
        self.assertTrue(b["download"].startswith("range-parallel ("))
        self.assertEqual(b["size"], BIG_LEN)
        # the 1-byte ranged probe (bytes=0-0) preceded the chunk pulls
        probes = [c for c in fake.calls if c["range"] == "bytes=0-0"]
        self.assertEqual(len(probes), 1)


class TestSourceMapProbe(unittest.TestCase):
    """(5) real parseable .map -> js_sourcemap_exposure; 200-but-HTML at .map -> not reported."""

    def test_real_map_reported_html_fake_positive_not_reported(self):
        fake = FakeHttp()
        default_small(fake)
        fake.add_bundle(CLEAN_URL, CLEAN_BODY)
        fake.add_map(SMALL_URL + ".map", 200, VALID_MAP_BODY)
        fake.add_map(CLEAN_URL + ".map", 200, HTML_ERROR_BODY)  # fake positive
        res = scan(fake, [SMALL_URL, CLEAN_URL])
        maps = [f for f in res["findings"] if f["type"] == "js_sourcemap_exposure"]
        self.assertEqual(len(maps), 1)
        f = maps[0]
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["target"], SMALL_URL)
        self.assertEqual(f["confidence"], 0.85)
        joined = " ".join(f["evidence"])
        self.assertIn("HTTP 200", joined)
        self.assertIn("CWE-540", joined)
        self.assertIn("source files referenced: 3", joined)
        self.assertIn("sourcesContent present", joined)
        self.assertIn("reconstruct", f["next_action"])
        # the fake positive is explicitly explained away, never reported
        clean_rec = next(b for b in res["metadata"]["bundles"] if b["url"] == CLEAN_URL)
        self.assertFalse(clean_rec["sourcemap"]["exposed"])
        self.assertIn("not valid JSON", clean_rec["sourcemap"]["note"])
        self.assertTrue(any("not a source map" in e for e in res["evidence"]))

    def test_404_map_is_silent_normal_case(self):
        fake = FakeHttp()
        default_small(fake)
        res = scan(fake, [SMALL_URL])
        self.assertEqual([f for f in res["findings"]
                          if f["type"] == "js_sourcemap_exposure"], [])
        sm = res["metadata"]["bundles"][0]["sourcemap"]
        self.assertFalse(sm["exposed"])
        self.assertEqual(sm["status"], 404)


class TestBatchIsolation(unittest.TestCase):
    """(6) one dead bundle in a multi-bundle run -> captured in errors, rest still processed."""

    def test_dead_bundle_does_not_kill_the_run(self):
        fake = FakeHttp()
        default_small(fake)
        fake.add_bundle(CLEAN_URL, CLEAN_BODY)
        fake.error_urls.add(DEAD_URL)
        res = scan(fake, [SMALL_URL, DEAD_URL, CLEAN_URL])
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["target"], "batch:3 bundles")
        self.assertTrue(any(DEAD_URL in e and "FETCH_FAILED" in e for e in res["errors"]))
        stats = {b["url"]: b for b in res["metadata"]["bundles"]}
        self.assertEqual(stats[DEAD_URL]["status"], "error")
        self.assertEqual(stats[SMALL_URL]["status"], "ok")
        self.assertEqual(stats[CLEAN_URL]["status"], "ok")
        # the .map probe was skipped for the dead host, not silently dropped
        self.assertFalse(stats[DEAD_URL]["sourcemap"]["probed"])
        self.assertIn("skipped", stats[DEAD_URL]["sourcemap"]["note"])
        # the living bundles were fully processed
        kinds = {f["kind"] for f in res["findings"] if f["type"] == "js_secret"}
        self.assertIn("stripe_secret_key", kinds)
        summary = next(f for f in res["findings"] if f["type"] == "js_endpoint_summary")
        self.assertIn("2/3 ok", summary["evidence"][0])

    def test_dedup_across_bundles_and_dup_counting(self):
        fake = FakeHttp()
        other_url = "https://fixtures-cdn.example.invalid/js/copy.js"
        fake.add_bundle(SMALL_URL, SMALL_BODY)
        fake.add_bundle(other_url, SMALL_BODY)  # identical bundle under a second URL
        res = scan(fake, [SMALL_URL, other_url])
        secrets = [f for f in res["findings"] if f["type"] == "js_secret"]
        kinds = [f["kind"] for f in secrets]
        self.assertEqual(len(kinds), len(set(kinds)))  # deduped, not doubled
        aws = next(f for f in secrets if f["kind"] == "aws_access_key_id")
        self.assertIn("also seen in 1 other bundle(s)", " ".join(aws["evidence"]))
        self.assertEqual(res["metadata"]["totals"]["secret_patterns"], len(secrets))


class TestMiningHelpers(unittest.TestCase):
    def test_unknown_size_still_processed_with_explicit_warning(self):
        fake = FakeHttp()
        fake.add_bundle(SMALL_URL, SMALL_BODY, cl=None, ar=None)
        res = scan(fake, [SMALL_URL])
        b = res["metadata"]["bundles"][0]
        self.assertEqual(b["status"], "ok")
        self.assertIsNone(b["content_length"])
        self.assertTrue(any("could NOT be asserted" in e for e in res["evidence"]))
        kinds = {f["kind"] for f in res["findings"] if f["type"] == "js_secret"}
        self.assertIn("aws_access_key_id", kinds)

    def test_range_ignored_by_server_falls_back_to_slicing(self):
        fake = FakeHttp()
        fake.add_bundle(SMALL_URL, SMALL_BODY, ignore_range=True)
        res = scan(fake, [SMALL_URL], range_chunks=3, chunk_threshold_mb=0)
        b = res["metadata"]["bundles"][0]
        self.assertEqual(b["status"], "ok")
        self.assertEqual(b["size"], len(SMALL_BODY))
        kinds = {f["kind"] for f in res["findings"] if f["type"] == "js_secret"}
        self.assertIn("aws_access_key_id", kinds)

    def test_context_snippet_and_uri_scheme_matches(self):
        text = 'var u = "mongodb+srv://user:pw@mongo.fixture.invalid/db";'
        mined = jr.mine_text(text)
        self.assertEqual(mined["secrets"][0]["kind"], "mongodb_uri")
        self.assertEqual(mined["secrets"][0]["match"], "mongodb+srv://")  # doc regex matches the scheme
        self.assertIn("mongo.fixture.invalid", mined["secrets"][0]["context"])


class TestCLIContract(unittest.TestCase):
    """(7) mirrors TestCLIContract from the two prior suites; aggregate-not-per-url shape."""

    def test_json_output_shape_and_exit_code(self):
        fake = FakeHttp()
        default_small(fake)
        stdout = io.StringIO()
        with mock.patch.object(jr, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stdout(stdout):
            rc = jr.main(["--json", "--quiet", SMALL_URL])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        # ONE aggregate object for the whole batch — never an array of per-URL objects
        self.assertIsInstance(payload, dict)
        for key in ("tool", "target", "timestamp", "status", "findings", "evidence",
                    "errors", "metadata"):
            self.assertIn(key, payload)
        self.assertEqual(payload["tool"], "js_recon")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["target"], SMALL_URL)
        for f in payload["findings"]:
            for key in ("type", "severity", "confidence", "target", "evidence", "source",
                        "next_action"):
                self.assertIn(key, f)
            self.assertEqual(f["source"], "js_recon.py")
        b = payload["metadata"]["bundles"][0]
        for key in ("url", "size", "download", "truncated", "status"):
            self.assertIn(key, b)
        self.assertIn("totals", payload["metadata"])

    def test_batch_target_label(self):
        fake = FakeHttp()
        default_small(fake)
        fake.add_bundle(CLEAN_URL, CLEAN_BODY)
        stdout = io.StringIO()
        with mock.patch.object(jr, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stdout(stdout):
            rc = jr.main(["--json", "--quiet", SMALL_URL, CLEAN_URL])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["target"], "batch:2 bundles")
        self.assertEqual(len(payload["metadata"]["bundles"]), 2)

    def test_range_flags_plumbed_through(self):
        fake = FakeHttp()
        fake.add_bundle(SMALL_URL, SMALL_BODY)
        stdout = io.StringIO()
        with mock.patch.object(jr, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stdout(stdout):
            rc = jr.main(["--json", "--quiet", "--range-chunks", "3",
                          "--chunk-threshold-mb", "0", SMALL_URL])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["metadata"]["range_chunks"], 3)
        self.assertEqual(payload["metadata"]["chunk_threshold_bytes"], 0)
        self.assertEqual(payload["metadata"]["bundles"][0]["download"],
                         "range-parallel (3 chunks)")
        self.assertEqual(len(fake.range_calls(SMALL_URL)), 3)

    def test_duplicate_urls_deduped(self):
        fake = FakeHttp()
        default_small(fake)
        stdout = io.StringIO()
        with mock.patch.object(jr, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stdout(stdout):
            rc = jr.main(["--json", "--quiet", SMALL_URL, SMALL_URL])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(len(payload["metadata"]["bundles"]), 1)
        self.assertEqual(payload["target"], SMALL_URL)

    def test_all_bundles_failed_still_success_exit_zero(self):
        fake = FakeHttp()
        fake.error_urls.add(DEAD_URL)
        stdout = io.StringIO()
        with mock.patch.object(jr, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stdout(stdout):
            rc = jr.main(["--json", "--quiet", DEAD_URL])
        self.assertEqual(rc, 0)  # completed scan, not a hard error
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["findings"], [])
        self.assertTrue(payload["errors"])

    def test_hard_errors_exit_nonzero(self):
        fake = FakeHttp()
        with self.assertRaises(SystemExit) as cm:  # no targets at all -> usage error
            jr.main([])
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(jr.main(["-l", str(REPO_ROOT / "tests" / "missing-file.txt")]), 2)
        with self.assertRaises(SystemExit) as cm:  # --timeout 0 -> usage error
            jr.main([SMALL_URL, "--timeout", "0"])
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit) as cm:  # --threads 0 -> usage error
            jr.main([SMALL_URL, "--threads", "0"])
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit) as cm:  # --range-chunks 0 -> usage error
            jr.main([SMALL_URL, "--range-chunks", "0"])
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit) as cm:  # negative threshold -> usage error
            jr.main([SMALL_URL, "--chunk-threshold-mb", "-1"])
        self.assertEqual(cm.exception.code, 2)

    def test_list_file_processed_in_order(self):
        fake = FakeHttp()
        default_small(fake)
        fake.add_bundle(CLEAN_URL, CLEAN_BODY)
        listfile = JS_FIXTURES / "js_list_smoke.txt"
        listfile.write_text(
            "# recon/js.txt-style list\n%s\n\n%s\n" % (SMALL_URL, CLEAN_URL),
            encoding="utf-8")
        try:
            stdout = io.StringIO()
            with mock.patch.object(jr, "http_fetch", fake.http_fetch), \
                 contextlib.redirect_stdout(stdout):
                rc = jr.main(["--json", "--quiet", "-l", str(listfile)])
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual([b["url"] for b in payload["metadata"]["bundles"]],
                             [SMALL_URL, CLEAN_URL])
        finally:
            listfile.unlink()

    def test_human_mode_prints_summary_and_next_hint(self):
        fake = FakeHttp()
        default_small(fake)
        stderr = io.StringIO()
        with mock.patch.object(jr, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stderr(stderr), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = jr.main([SMALL_URL])  # no --json/--quiet
        self.assertEqual(rc, 0)
        err = stderr.getvalue()
        self.assertIn(SMALL_URL, err)
        self.assertIn("Next:", err)
        self.assertIn("validate.md", err)

    def test_output_file_written(self):
        fake = FakeHttp()
        default_small(fake)
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "js.json")
            stderr = io.StringIO()
            with mock.patch.object(jr, "http_fetch", fake.http_fetch), \
                 contextlib.redirect_stderr(stderr), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = jr.main([SMALL_URL, "--json", "--output", out])
            self.assertEqual(rc, 0)
            payload = json.loads(Path(out).read_text(encoding="utf-8"))
            self.assertEqual(payload["tool"], "js_recon")


if __name__ == "__main__":
    unittest.main()
