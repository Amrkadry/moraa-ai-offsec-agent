#!/usr/bin/env python3
"""Offline tests for scripts/cms_detect.py (TASK-003).

stdlib unittest + unittest.mock only. No real network calls: HTTP is mocked at the module's
single network seam, probe_http — the same testability pattern subdomain_takeover.py uses
for probe_http/run_dig. Pipeline logic, weighted-scoring threshold, adaptive follow-up
behavior, degradation paths, DB schema, and the JSON output contract are all tested
offline; live smoke runs (wordpress.org / example.com / .invalid) are a separate
verification step, not part of the suite.

Run:  python3 -m unittest discover -s tests -p "test_cms_detect.py" -v
"""

import contextlib
import io
import json
import re
import sys
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import cms_detect as cd  # noqa: E402

HTTP_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "http"


def fx(name: str) -> str:
    return (HTTP_FIXTURES / name).read_text(encoding="utf-8")


class FakeHttp:
    """Standalone-in for probe_http. Routes full URL paths (optionally with query) to
    (status, headers, body) tuples; a dict route {"error": "..."} simulates a transport
    failure; anything unrouted falls through to `default` (a 404, like a sane server).
    Records every call as "METHOD path[?query]" for the adaptive no-blind-sweep assertions."""

    def __init__(self, routes=None, default=(404, {}, "File not found.")):
        self.routes = routes or {}
        self.default = default
        self.calls: list[str] = []

    def probe_http(self, url, timeout, data=None):
        parts = urllib.parse.urlsplit(url)
        path_q = parts.path + (("?" + parts.query) if parts.query else "")
        self.calls.append(("POST" if data is not None else "GET") + " " + path_q)
        if path_q in self.routes:
            route = self.routes[path_q]
        elif parts.path in self.routes:
            route = self.routes[parts.path]
        elif parts.path in ("", "/") and "/" in self.routes:
            route = self.routes["/"]  # root route answers ONLY for the root path
        else:
            route = self.default
        if isinstance(route, dict) and "error" in route:
            return {"url": url, "final_url": url, "status": None, "headers": {},
                    "body": None, "error": route["error"], "redirects": []}
        status, headers, body = route
        return {"url": url, "final_url": url, "status": status,
                "headers": {k.lower(): v for k, v in headers.items()},
                "body": body, "error": None, "redirects": []}


def scan(fake, target, timeout=5.0):
    """Run scan_target with HTTP fully mocked at probe_http."""
    with mock.patch.object(cd, "probe_http", fake.probe_http):
        return cd.scan_target(target, cd.load_fingerprints(), timeout=timeout)


class TestWordPressPipeline(unittest.TestCase):
    """(1) Realistic WP signals -> identified above threshold, version extracted,
    follow-ups run — and ONLY WordPress follow-ups (no blind sweep)."""

    def setUp(self):
        self.fake = FakeHttp(routes={
            "/": (200, {"X-Powered-By": "PHP/8.1", "Content-Type": "text/html"},
                  fx("wordpress_home.html")),
            "/wp-includes/js/wp-emoji-release.min.js": (200, {}, "/*! fixture */"),
            "/wp-login.php": (200, {}, "<html>fixture login form</html>"),
            "/readme.html": (200, {"Content-Type": "text/html"}, fx("wp_readme.html")),
            "/wp-json/wp/v2/users": (200, {"Content-Type": "application/json"},
                                     fx("wp_users.json")),
            "/wp-content/debug.log": (200, {}, "[26-Sep-2026 03:11:02 UTC] PHP Notice: "
                                               "fixture notice in /var/www/fixture/wp-content/plugins/fix/fix.php on line 9"),
            "/xmlrpc.php": (405, {"Allow": "POST"},
                            "XML-RPC server accepts only POST requests."),
        })
        self.res = scan(self.fake, "https://fixture-wp.test/")

    def test_identified_above_threshold(self):
        f = self.res["findings"][0]
        self.assertEqual(f["cms"], "WordPress")
        self.assertEqual(f["severity"], "info")  # detection itself is always info
        self.assertGreaterEqual(f["confidence"], cd.CONFIDENCE_THRESHOLD)
        self.assertTrue(any("verdict: WordPress identified" in e
                            for e in self.res["evidence"]))

    def test_version_extracted(self):
        f = self.res["findings"][0]
        self.assertEqual(f["version"], "6.4.2")
        self.assertTrue(any("version: 6.4.2" in e for e in self.res["evidence"]))

    def test_followups_run_and_exposures_flagged(self):
        # the three WordPress follow-up paths were requested...
        for path in ("/wp-json/wp/v2/users", "/wp-content/debug.log", "/xmlrpc.php"):
            self.assertIn("GET " + path, self.fake.calls)
        # ...the actionable ones produced their own low findings (base stays info)
        exposures = [f for f in self.res["findings"] if f["type"] == "cms_exposure"]
        self.assertGreaterEqual(len(exposures), 3)
        for f in exposures:
            self.assertEqual(f["severity"], "low")
        user_enum = next(f for f in exposures if "user enumeration" in f["next_action"])
        # extracted FACT, not a raw dump: usernames, with count
        self.assertIn("usernames: admin, editor (2 user(s))",
                      " ".join(user_enum["evidence"]))
        base = self.res["findings"][0]
        self.assertIn("wp-json/wp/v2/users", base["next_action"])

    def test_no_blind_sweep_of_other_cms_paths(self):
        for foreign in ("/administrator/manifests/files/joomla.xml",
                        "/core/misc/drupal.js", "/version.php",
                        "/magento_version", "/lib/ajax/service-nologin.php"):
            self.assertNotIn("GET " + foreign, self.fake.calls)


class TestJoomlaPipeline(unittest.TestCase):
    def test_version_and_cve_2023_23752_check(self):
        fake = FakeHttp(routes={
            "/": (200, {"Content-Type": "text/html"}, fx("joomla_home.html")),
            "/administrator/manifests/files/joomla.xml":
                (200, {}, "<extension><name>files_joomla</name>"
                          "<version>4.2.9</version></extension>"),
            "/language/en-GB/en-GB.xml": (200, {}, "<metafile><version>4.2.9</version></metafile>"),
            "/administrator/": (200, {}, "<html>fixture admin login</html>"),
            "/api/index.php/v1/config/application?public=true":
                (200, {"Content-Type": "application/json"},
                 '{"data":[{"type":"application","attributes":{"user":"fixturedbuser",'
                 '"password":"fixturedbpass","db":"fixture_db","dbtype":"mysqli",'
                 '"host":"localhost"}}]}'),
        })
        res = scan(fake, "fixture-j.test")  # bare host: https fallback exercised too
        f = res["findings"][0]
        self.assertEqual(f["cms"], "Joomla")
        self.assertEqual(f["version"], "4.2.9")
        exposures = [x for x in res["findings"] if x["type"] == "cms_exposure"]
        self.assertEqual(len(exposures), 2)
        joined = json.dumps(exposures)
        self.assertIn("CVE-2023-23752", joined)
        self.assertIn("fixturedbpass", joined)  # leak named in evidence, as it should be
        self.assertIn("GET /api/index.php/v1/config/application?public=true", fake.calls)


class TestDrupalPipeline(unittest.TestCase):
    def test_header_plus_body_identification_and_clean_result(self):
        fake = FakeHttp(routes={
            "/": (200, {"X-Generator": "Drupal 10 (https://www.drupal.org)"},
                  fx("drupal_home.html")),
            "/core/misc/drupal.js": (200, {}, "fixture drupal js"),
            "/user/register": (200, {}, "<html>fixture registration form</html>"),
        })
        res = scan(fake, "fixture-d.test")
        f = res["findings"][0]
        self.assertEqual(f["cms"], "Drupal")
        self.assertEqual(f["version"], "10")
        # no CHANGELOG exposure on a sane deploy: zero cms_exposure findings
        self.assertEqual([x for x in res["findings"] if x["type"] == "cms_exposure"], [])
        self.assertTrue(any("/core/CHANGELOG.txt" in c for c in fake.calls))
        self.assertTrue(any("/user/register" in c for c in fake.calls))


class TestMoodlePipeline(unittest.TestCase):
    def test_cookie_and_cfg_identify_and_config_dump_facts_extracted(self):
        fake = FakeHttp(routes={
            "/": (200, {"Set-Cookie": "MoodleSession=fixture12345"}, fx("moodle_home.html")),
            "/lib/editor/tiny/js/tinymce/tinymce.min.js": (200, {}, "fixture tinymce"),
            "/admin/tool/mfa/index.php": (303, {}, ""),
            "/login/index.php": (200, {}, "<html>fixture login</html>"),
            "/version.php": (200, {}, ""),  # sane deploy: 200 + 0 bytes -> no disclosure
            "/lib/ajax/service-nologin.php?info=tool_mobile_get_public_config":
                (200, {"Content-Type": "application/json"}, fx("moodle_config.json")),
        })
        res = scan(fake, "fixture-m.test")
        f = res["findings"][0]
        self.assertEqual(f["cms"], "Moodle")
        self.assertIsNone(f["version"])  # version.php empty: no fabricated version
        self.assertTrue(any("registerauth=email" in e for e in res["evidence"]))
        self.assertTrue(any("identityproviders=1: Fixture SSO" in e for e in res["evidence"]))
        # the config dump is by-design public (cms-moodle.md §0) — evidence, never a low
        self.assertEqual([x for x in res["findings"] if x["type"] == "cms_exposure"], [])
        self.assertIn("POST /lib/ajax/service-nologin.php?info=tool_mobile_get_public_config",
                      fake.calls)


class TestGhostPipeline(unittest.TestCase):
    def test_powered_by_header_identifies_without_fabricating_version(self):
        body = ('<html><head><title>fixture pub</title></head><body>'
                '<img src="/content/images/size/w600/2026/10/fixture.jpg">'
                '<script src="/public/ghost-sdk.min.js"></script></body></html>')
        fake = FakeHttp(routes={
            "/": (200, {"X-Powered-By": "Ghost"}, body),
            "/ghost/": (200, {}, "<html>fixture admin</html>"),
        })
        res = scan(fake, "fixture-g.test")
        f = res["findings"][0]
        self.assertEqual(f["cms"], "Ghost")
        self.assertIsNone(f["version"])  # header carries no version -> None, not a guess
        self.assertEqual([x for x in res["findings"] if x["type"] == "cms_exposure"], [])


class TestAdaptiveScoring(unittest.TestCase):
    """(2) + (3) — the weighted-threshold discipline."""

    def test_unknown_site_below_threshold_cms_null_and_no_followup_requests(self):
        fake = FakeHttp(routes={"/": (200, {"Server": "nginx/1.24.0"}, fx("generic_home.html"))})
        res = scan(fake, "fixture-static.test")
        f = res["findings"][0]
        self.assertIsNone(f["cms"])
        self.assertEqual(f["severity"], "info")
        self.assertIn("generic tech fingerprint", f["next_action"])
        # every candidate scored, winner 0.0, runner-up visible in metadata
        self.assertEqual(max(s["score"] for s in res["metadata"]["cms_scores"]), 0.0)
        self.assertEqual(len(res["metadata"]["cms_scores"]), 6)
        # strictly adaptive: exactly one request (discovery), nothing else
        self.assertEqual(len(fake.calls), 1)
        # generic tech actually observed is reported with evidence
        self.assertEqual(res["metadata"]["generic_tech"]["server"], "nginx/1.24.0")
        self.assertTrue(any("Server: nginx/1.24.0" in e for e in res["evidence"]))

    def test_single_weak_signal_stays_below_threshold(self):
        # one incidental "wp-json" mention (weight 0.35) + all path probes 404:
        # stays below threshold, and — critically — no WordPress follow-up is fired.
        fake = FakeHttp(routes={"/": (200, {}, fx("weak_wp_home.html"))})
        res = scan(fake, "fixture-weak.test")
        f = res["findings"][0]
        self.assertIsNone(f["cms"])
        self.assertFalse(any("identified — score" in e for e in res["evidence"]))
        self.assertTrue(any("not identified" in e for e in res["evidence"]))
        wp = next(s for s in res["metadata"]["cms_scores"] if s["cms"] == "WordPress")
        self.assertLess(wp["score"], cd.CONFIDENCE_THRESHOLD)
        # path probes for the candidate DID happen (adaptive confirmation), follow-ups did not
        self.assertIn("GET /wp-login.php", fake.calls)
        self.assertNotIn("GET /wp-json/wp/v2/users", fake.calls)
        self.assertEqual(res["errors"], [])


class TestDegradation(unittest.TestCase):
    """(4) probe failure -> success-status result with captured errors, never a crash."""

    def test_discovery_failure_is_inconclusive_equivalent(self):
        err = {"error": "URLError: <urlopen error [Errno -2] fixture resolution failure>"}
        fake = FakeHttp(routes={"/": err})
        res = scan(fake, "fixture-dead.test")
        self.assertEqual(res["status"], "success")
        f = res["findings"][0]
        self.assertIsNone(f["cms"])
        self.assertEqual(f["severity"], "info")
        self.assertEqual(len(res["errors"]), 2)  # https + http attempts both captured
        self.assertTrue(all("fixture-dead.test" in e for e in res["errors"]))
        self.assertIn("unreachable", f["next_action"])
        # no follow-up or version requests against a dead target
        self.assertEqual(len(fake.calls), 2)


class TestHelpers(unittest.TestCase):
    def test_normalize_target(self):
        self.assertEqual(cd.normalize_target("fixture.test"),
                         ["https://fixture.test", "http://fixture.test"])
        self.assertEqual(cd.normalize_target("https://fixture.test/a"),
                         ["https://fixture.test/a"])
        self.assertEqual(cd.normalize_target("http://fixture.test/"), ["http://fixture.test"])

    def test_extract_generators_attribute_order_agnostic(self):
        body = ('<meta content="WordPress 6.1" name="generator">'
                '<meta name="generator" content="Another">'
                '<meta name="viewport" content="width=device-width">')
        gens = cd.extract_generators(body)
        self.assertEqual(sorted(gens), ["Another", "WordPress 6.1"])

    def test_broken_db_regex_never_raises(self):
        sig = {"type": "body_regex", "detail": "broken", "match": "([unclosed", "weight": 0.5}
        self.assertFalse(cd._signal_matched(sig, {}, [], "anything", None))


class TestFingerprintDB(unittest.TestCase):
    """(5) The data file itself is part of the contract."""

    def setUp(self):
        self.fps = cd.load_fingerprints()

    def test_canonical_cms_present_no_duplicates(self):
        names = [fp["cms"] for fp in self.fps]
        self.assertEqual(len(names), len(set(names)))
        for cms in ("WordPress", "Joomla", "Drupal", "Moodle", "Ghost", "Magento"):
            self.assertIn(cms, names)

    def test_every_entry_has_required_fields(self):
        for fp in self.fps:
            for key in ("cms", "confidence_basis", "confidence_signals",
                        "version_signals", "follow_up"):
                self.assertIn(key, fp, f"{fp.get('cms')}: missing {key}")
            self.assertIn(fp["confidence_basis"], ("well-documented", "community-report"))
            self.assertTrue(fp["confidence_signals"], f"{fp['cms']}: no signals")
            self.assertTrue(fp["version_signals"], f"{fp['cms']}: no version signals")
            self.assertTrue(fp["follow_up"], f"{fp['cms']}: no follow-ups")

    def test_signal_schema(self):
        ok_types = {"header", "body_regex", "path_exists", "meta_generator"}
        for fp in self.fps:
            for sig in fp["confidence_signals"]:
                self.assertIn(sig["type"], ok_types, f"{fp['cms']}: {sig}")
                self.assertTrue(sig.get("detail"), f"{fp['cms']}: signal missing detail")
                self.assertTrue(sig.get("match"), f"{fp['cms']}: signal missing match")
                w = sig["weight"]
                self.assertIsInstance(w, (int, float))
                self.assertGreater(w, 0.0)
                self.assertLessEqual(w, 1.0)

    def test_version_and_followup_schema(self):
        ok_sources = {"meta_generator", "header", "body", "path"}
        for fp in self.fps:
            for vs in fp["version_signals"]:
                self.assertIn(vs["source"], ok_sources, f"{fp['cms']}: {vs}")
                self.assertTrue(vs.get("regex"), f"{fp['cms']}: version signal missing regex")
                if vs["source"] == "path":
                    self.assertTrue(vs.get("path", "").startswith("/"))
                if vs["source"] == "header":
                    self.assertTrue(vs.get("header"))
            for fu in fp["follow_up"]:
                self.assertTrue(fu.get("path", "").startswith("/"), f"{fp['cms']}: {fu}")
                self.assertTrue(fu.get("purpose"), f"{fp['cms']}: follow-up missing purpose")
                self.assertIn(fu.get("method", "GET"), ("GET", "POST"))
                if fu.get("method") == "POST":
                    self.assertIn("body", fu)
                if "expose_when" in fu:
                    ew = fu["expose_when"]
                    self.assertIsInstance(ew.get("status"), list)
                    self.assertTrue(ew.get("body_regex"))

    def test_all_regexes_compile(self):
        for fp in self.fps:
            for sig in fp["confidence_signals"]:
                if sig["type"] == "body_regex":
                    try:
                        re.compile(sig["match"])
                    except re.error as e:
                        self.fail(f"{fp['cms']}: bad body_regex {sig['match']!r}: {e}")
            for vs in fp["version_signals"]:
                try:
                    re.compile(vs["regex"])
                except re.error as e:
                    self.fail(f"{fp['cms']}: bad version regex {vs['regex']!r}: {e}")
            for fu in fp["follow_up"]:
                if "expose_when" in fu:
                    try:
                        re.compile(fu["expose_when"]["body_regex"])
                    except re.error as e:
                        self.fail(f"{fp['cms']}: bad expose_when regex: {e}")

    def test_every_cms_can_reach_threshold_with_corroboration(self):
        # weighted-signal discipline: no single signal below the threshold weight may
        # identify a CMS on its own (true by construction — sums start at that weight),
        # and every CMS must be reachable via its two strongest signals combined.
        for fp in self.fps:
            top2 = sum(sorted((s["weight"] for s in fp["confidence_signals"]), reverse=True)[:2])
            self.assertGreaterEqual(top2, cd.CONFIDENCE_THRESHOLD,
                                    f"{fp['cms']}: cannot reach threshold with corroboration")
            weakest = min(s["weight"] for s in fp["confidence_signals"])
            self.assertLess(weakest, cd.CONFIDENCE_THRESHOLD,
                            f"{fp['cms']}: no corroborating weak signals at all")

    def test_threshold_documented_constant(self):
        self.assertTrue(0.0 < cd.CONFIDENCE_THRESHOLD < 1.0)


class TestCLIContract(unittest.TestCase):
    """(6) Mirrors test_subdomain_takeover.TestCLIContract."""

    def test_json_output_shape_and_exit_code(self):
        fake = FakeHttp(routes={
            "/": (200, {"X-Powered-By": "PHP/8.1"}, fx("wordpress_home.html")),
            "/wp-includes/js/wp-emoji-release.min.js": (200, {}, "x"),
            "/wp-login.php": (200, {}, "x"),
            "/readme.html": (200, {}, fx("wp_readme.html")),
            "/wp-json/wp/v2/users": (200, {}, fx("wp_users.json")),
            "/wp-content/debug.log": (200, {}, "PHP Notice: fixture"),
            "/xmlrpc.php": (405, {}, "XML-RPC server accepts only POST requests."),
        })
        stdout = io.StringIO()
        with mock.patch.object(cd, "probe_http", fake.probe_http), \
             contextlib.redirect_stdout(stdout):
            rc = cd.main(["--json", "--quiet", "fixture-wp.test"])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        for key in ("tool", "target", "timestamp", "status", "findings", "evidence",
                    "errors", "metadata"):
            self.assertIn(key, payload)
        self.assertEqual(payload["tool"], "cms_detect")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["target"], "fixture-wp.test")
        f = payload["findings"][0]
        for key in ("type", "severity", "confidence", "target", "evidence", "source",
                    "next_action", "cms", "version"):
            self.assertIn(key, f)
        self.assertEqual(f["type"], "cms_detection")
        self.assertEqual(f["source"], "cms_detect.py")
        self.assertEqual(f["cms"], "WordPress")
        self.assertIn("threshold", payload["metadata"])
        self.assertIn("requests_made", payload["metadata"])
        self.assertIn("generic_tech", payload["metadata"])

    def test_hard_errors_exit_nonzero(self):
        with self.assertRaises(SystemExit) as cm:  # no targets at all -> usage error
            cd.main([])
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(cd.main(["-l", str(REPO_ROOT / "tests" / "missing-file.txt")]), 2)
        with self.assertRaises(SystemExit) as cm:  # --timeout 0 -> usage error
            cd.main(["fixture.test", "--timeout", "0"])
        self.assertEqual(cm.exception.code, 2)

    def test_list_file_targets_processed_in_order(self):
        listfile = REPO_ROOT / "tests" / "fixtures" / "http" / "list_smoke.txt"
        listfile.write_text("https://a.test/\n# comment\nb.test\n", encoding="utf-8")
        self.addCleanup(listfile.unlink)
        fake = FakeHttp()  # default 404: every target scans, nothing identified
        stdout = io.StringIO()
        with mock.patch.object(cd, "probe_http", fake.probe_http), \
             contextlib.redirect_stdout(stdout):
            rc = cd.main(["--json", "--quiet", "-l", str(listfile)])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIsInstance(payload, list)
        self.assertEqual([r["target"] for r in payload], ["https://a.test/", "b.test"])
        for r in payload:
            self.assertIsNone(r["findings"][0]["cms"])

    def test_human_mode_prints_summary_and_next_hint(self):
        fake = FakeHttp(routes={"/": (200, {"Server": "nginx"}, fx("generic_home.html"))})
        stderr = io.StringIO()
        with mock.patch.object(cd, "probe_http", fake.probe_http), \
             contextlib.redirect_stderr(stderr), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = cd.main(["fixture-static.test"])  # no --json/--quiet
        self.assertEqual(rc, 0)
        err = stderr.getvalue()
        self.assertIn("no CMS identified", err)
        self.assertIn("Next:", err)


if __name__ == "__main__":
    unittest.main()
