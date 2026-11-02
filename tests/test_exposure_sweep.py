#!/usr/bin/env python3
"""Offline tests for scripts/exposure_sweep.py (TASK-010).

stdlib unittest + unittest.mock only. No real network calls: HTTP is mocked at the module's
single network seam, http_fetch (imported from js_recon and bound as exposure_sweep.http_fetch
— patching that name patches everything). Pipeline logic (tier-1/tier-2 sweep, the recon.md
§4d severity ladder, the two separate secret signals, git origin-remote extraction with the
distinct credential-bearing-remote finding, best-effort .DS_Store extraction, catch-all
soft-200 guards, per-host fault isolation), the pure helpers, and the JSON output contract
are all tested offline; live smoke runs (example.com / .invalid) are a separate verification
step, not part of the suite.

All credential-shaped strings in fixtures are deliberately synthetic placeholders
(e.g. AWS's published example key AKIAIOSFODNN7EXAMPLE, passwords on RFC 2606 .invalid
hosts) — never real-looking credentials.

Run:  python3 -m unittest discover -s tests -p "test_exposure_sweep.py" -v
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

import exposure_sweep as es  # noqa: E402

HOST_A = "https://sweep-a.example.invalid"
HOST_B = "https://sweep-b.example.invalid"
DEAD_HOST = "https://dead-sweep.example.invalid"

GIT_HEAD_BODY = b"ref: refs/heads/main\n"
GIT_CONFIG_PLAIN = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = true\n"
    '[remote "origin"]\n'
    "\turl = https://git.internal.example.invalid/team/app.git\n"
    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n").encode()
GIT_CONFIG_CREDS = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    '[remote "origin"]\n'
    "\turl = https://ci-bot:not-a-real-password@example-git.invalid/team/app.git\n"
    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n").encode()
CRED_USER, CRED_PASS = "ci-bot", "not-a-real-password"
ENV_AWS_BODY = b"APP_NAME=demo\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_HOST=localhost\n"
ENV_PHRASE_BODY = b"DB_PASSWORD=placeholder-not-real\nAPP_NAME=demo\n"
HTML_BODY = (b"<html><head><title>App</title></head>"
             b"<body><form>password: <input type=password></form></body></html>")
DS_BODY = (b"\x00\x00\x00\x01Bud1"
           b"\x00\x01\x00\x00Iloc\x00\x00\x00\x01"
           b"\x00\x00\x00\x0abackup.zip"
           + "database.sql".encode("utf-16-be")
           + b"\x00\x00bwsp\x00\x00\x02"
           + b"config_old.php")

N_TIER_PATHS = len(es.TIER1_PATHS) + len(es.TIER2_PATHS)  # 14 + 5 = 19


def _resp(url, status, body):
    return {"url": url, "final_url": url, "status": status,
            "headers": {}, "body": body, "over_cap": False, "error": None, "redirects": []}


def _err(url, message):
    return {"url": url, "final_url": url, "status": None, "headers": {}, "body": None,
            "over_cap": False, "error": message, "redirects": []}


class FakeHttp:
    """Standalone-in for http_fetch. Routes FULL URLs to (status, body); anything unrouted
    answers `default` (a 404, like a sane server — every §4d path misses). Hosts listed in
    error_prefixes fail every request at transport level (the dead-host fixture). Every
    call's URL is recorded for request-count assertions."""

    def __init__(self, default=(404, b"Not Found")):
        self.routes = {}
        self.error_prefixes = set()
        self.default = default
        self.calls: list[str] = []

    def add(self, url, status=200, body=b""):
        self.routes[url] = (status, body)

    def http_fetch(self, url, timeout, method="GET", extra_headers=None, max_bytes=None):
        self.calls.append(url)
        for prefix in self.error_prefixes:
            if url.startswith(prefix):
                return _err(url, "URLError: <urlopen error fixture: name resolution failed>")
        status, body = self.routes.get(url, self.default)
        return _resp(url, status, body)


def sweep(fake, hosts, **kwargs):
    with mock.patch.object(es, "http_fetch", fake.http_fetch):
        return es.scan_hosts(hosts, **kwargs)


def hit_findings(res, path=None, variant=None):
    out = res["findings"]
    if path is not None:
        out = [f for f in out if f["path"] == path]
    if variant is not None:
        out = [f for f in out if f.get("variant") == variant]
    return out


class TestCleanHost(unittest.TestCase):
    """(1) every path 404s -> zero findings, misses counted in metadata, never enumerated."""

    def setUp(self):
        self.fake = FakeHttp()
        self.res = sweep(self.fake, [HOST_A])

    def test_zero_findings_and_counted_misses(self):
        self.assertEqual(self.res["status"], "success")
        self.assertEqual(self.res["findings"], [])
        h = self.res["metadata"]["hosts"][0]
        self.assertEqual(h["paths_tried"], N_TIER_PATHS)
        self.assertEqual(h["misses"], N_TIER_PATHS)
        self.assertEqual(h["hits"], 0)
        self.assertEqual(h["fetch_errors"], 0)
        self.assertEqual(self.res["metadata"]["totals"]["hits"], 0)

    def test_misses_not_enumerated_in_evidence(self):
        # the flood guard: 19 misses must appear ONLY as a count, never as evidence lines
        self.assertNotIn("HIT", " ".join(self.res["evidence"]))
        self.assertNotIn("FETCH_FAILED", " ".join(self.res["evidence"]))
        self.assertEqual(len(self.res["evidence"]), 0)
        self.assertEqual(len(self.res["errors"]), 0)

    def test_exactly_one_request_per_path_plus_root_probe(self):
        self.assertEqual(len(self.fake.calls), N_TIER_PATHS + 1)  # +1 root catch-all probe
        self.assertEqual(len([c for c in self.fake.calls if c.endswith("/.env")]), 1)

    def test_tiers_disjoint_and_verbatim(self):
        self.assertFalse(set(es.TIER1_PATHS) & set(es.TIER2_PATHS))
        for p in ("/.git/HEAD", "/.git/config", "/.git/logs/HEAD", "/.svn/wc.db",
                  "/.svn/entries", "/.hg/requires", "/.bzr/branch-format", "/.DS_Store",
                  "/.env", "/web.config", "/WEB-INF/web.xml", "/application.properties",
                  "/config.php.bak", "/backup.zip"):
            self.assertIn(p, es.TIER1_PATHS)  # recon.md §4d triage list, verbatim
        for p in ("/.env.production", "/connectionStrings.config", "/appsettings.json",
                  "/secrets.json", "/wp-config.php"):
            self.assertIn(p, es.TIER2_PATHS)  # §4d stack table minus tier-1 overlap


class TestGitHeadGenuine(unittest.TestCase):
    """(2) /.git/HEAD = 'ref: refs/heads/main' -> genuine-file recognition (not 'any 200'),
    low severity, next_action pointing at git-dumper."""

    def setUp(self):
        self.fake = FakeHttp()
        self.fake.add(HOST_A + "/.git/HEAD", 200, GIT_HEAD_BODY)
        self.res = sweep(self.fake, [HOST_A])

    def test_recognized_genuine_low(self):
        hits = hit_findings(self.res, path="/.git/HEAD")
        self.assertEqual(len(hits), 1)
        f = hits[0]
        self.assertEqual(f["type"], "source_disclosure")
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["confidence"], es.CONF_GENUINE)
        self.assertEqual(f["variant"], "git_head")
        self.assertEqual(f["source"], "exposure_sweep.py")
        joined = " ".join(f["evidence"])
        self.assertIn("ref: refs/", joined)
        self.assertIn("genuine git HEAD", joined)

    def test_next_action_points_at_git_dumper(self):
        f = hit_findings(self.res, path="/.git/HEAD")[0]
        self.assertIn("git-dumper", f["next_action"])
        self.assertIn("out of scope for this detector", f["next_action"])

    def test_config_refetched_once_and_remote_undetermined_noted(self):
        # §4d(b): HEAD hit -> config fetched again even though its tier-1 probe 404'd
        cfg_calls = [c for c in self.fake.calls if c.endswith("/.git/config")]
        self.assertEqual(len(cfg_calls), 2)  # tier-1 probe + the HEAD-triggered refetch
        f = hit_findings(self.res, path="/.git/HEAD")[0]
        self.assertIn("origin remote undetermined", " ".join(f["evidence"]))
        self.assertEqual(len(self.fake.calls), 1 + N_TIER_PATHS + 1)  # root + 19 + refetch


class TestGitCredentialedRemote(unittest.TestCase):
    """(3) git hit + /.git/config with url = https://user:pass@host/... -> the
    credential-bearing remote is its OWN distinct high-severity finding, password redacted."""

    def setUp(self):
        self.fake = FakeHttp()
        self.fake.add(HOST_A + "/.git/HEAD", 200, GIT_HEAD_BODY)
        self.fake.add(HOST_A + "/.git/config", 200, GIT_CONFIG_CREDS)
        self.res = sweep(self.fake, [HOST_A])

    def test_remote_credential_is_distinct_high_finding(self):
        remotes = hit_findings(self.res, variant="git_remote_credential")
        self.assertEqual(len(remotes), 1)
        f = remotes[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["confidence"], es.CONF_REMOTE_CREDS)
        self.assertEqual(f["target"], HOST_A + "/.git/config")
        self.assertNotEqual(f["target"], hit_findings(self.res, path="/.git/HEAD")[0]["target"])
        self.assertIn("validate.md", f["next_action"])
        self.assertIn("high, not critical", f["next_action"])

    def test_password_redacted_but_structure_proven(self):
        blob = json.dumps(self.res)
        self.assertNotIn(CRED_PASS, blob)  # never ship the literal credential in output
        f = hit_findings(self.res, variant="git_remote_credential")[0]
        joined = " ".join(f["evidence"])
        self.assertIn(CRED_USER + ":<redacted:%d-chars>@example-git.invalid" % len(CRED_PASS),
                      joined)
        self.assertIn("redacted", joined)

    def test_config_reused_not_refetched(self):
        self.assertEqual(len([c for c in self.fake.calls if c.endswith("/.git/config")]), 1)

    def test_both_git_findings_still_low(self):
        self.assertEqual(hit_findings(self.res, path="/.git/HEAD")[0]["severity"], "low")
        self.assertEqual(hit_findings(self.res, path="/.git/config")[0]["severity"], "low")

    def test_plain_remote_recorded_as_evidence_not_own_finding(self):
        # a non-credentialed remote only reveals the git provider/internal host — §4d(b)
        # makes ONLY the credential-bearing URL its own finding
        fake = FakeHttp()
        fake.add(HOST_B + "/.git/HEAD", 200, GIT_HEAD_BODY)
        fake.add(HOST_B + "/.git/config", 200, GIT_CONFIG_PLAIN)
        res = sweep(fake, [HOST_B])
        self.assertEqual(hit_findings(res, variant="git_remote_credential"), [])
        joined = " ".join(hit_findings(res, path="/.git/config")[0]["evidence"])
        self.assertIn("git remote URL: https://git.internal.example.invalid/team/app.git",
                      joined)
        self.assertIn("internal host", joined)


class TestSecretPatternEscalation(unittest.TestCase):
    """(4) config hit whose body matches a SECRET_PATTERNS regex (AWS's published example
    key) -> escalates to high with the 'regex match only, NOT verified live' language."""

    def setUp(self):
        self.fake = FakeHttp()
        self.fake.add(HOST_A + "/.env", 200, ENV_AWS_BODY)
        self.res = sweep(self.fake, [HOST_A])

    def test_escalates_to_high(self):
        f = hit_findings(self.res, path="/.env")[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["confidence"], es.CONF_PATTERN_TIER["medium"])
        joined = " ".join(f["evidence"])
        self.assertIn("AKIAIOSFODNN7EXAMPLE", joined)
        self.assertIn("kind=aws_access_key_id", joined)
        self.assertIn("SECRET_PATTERNS hit", joined)
        self.assertIn("NOT verified live", joined)

    def test_next_action_carries_the_gate(self):
        f = hit_findings(self.res, path="/.env")[0]
        self.assertIn("regex match only, NOT verified live — validate.md gate",
                      f["next_action"])

    def test_genuine_base_was_low_before_escalation(self):
        joined = " ".join(hit_findings(self.res, path="/.env")[0]["evidence"])
        self.assertIn("genuine config-style file", joined)  # ladder: low base, +pattern -> high


class TestPhraseOnlySignal(unittest.TestCase):
    """(5) catch-all phrase (DB_PASSWORD=) WITHOUT a SECRET_PATTERNS hit -> still recorded,
    at deliberately lower confidence than a true pattern hit."""

    def setUp(self):
        self.fake = FakeHttp()
        self.fake.add(HOST_A + "/.env", 200, ENV_PHRASE_BODY)
        self.res = sweep(self.fake, [HOST_A])

    def test_recorded_with_low_confidence(self):
        f = hit_findings(self.res, path="/.env")[0]
        self.assertEqual(f["confidence"], es.CONF_PHRASE)
        self.assertLess(f["confidence"], es.CONF_PATTERN_TIER["medium"])
        joined = " ".join(f["evidence"])
        self.assertIn("catch-all indicator phrase(s)", joined)
        self.assertIn("password (line 1)", joined)

    def test_no_pattern_hits_claimed(self):
        f = hit_findings(self.res, path="/.env")[0]
        self.assertNotIn("SECRET_PATTERNS hit", " ".join(f["evidence"]))
        self.assertNotIn("kind=", " ".join(f["evidence"]))

    def test_severity_stays_at_ladder_base(self):
        # the §4d ladder's high tier requires a verified secret PATTERN; a generic word is
        # an indicator — recorded, but it must not inflate severity (see module docstring)
        f = hit_findings(self.res, path="/.env")[0]
        self.assertEqual(f["severity"], "low")  # genuine file, no verified pattern
        self.assertIn("validate.md", f["next_action"])


class TestDsStoreExtraction(unittest.TestCase):
    """(6) .DS_Store best-effort filename extraction from a synthetic binary blob."""

    def setUp(self):
        self.fake = FakeHttp()
        self.fake.add(HOST_A + "/.DS_Store", 200, DS_BODY)
        self.res = sweep(self.fake, [HOST_A])

    def test_genuine_magic_recognized_low(self):
        f = hit_findings(self.res, path="/.DS_Store")[0]
        self.assertEqual(f["severity"], "low")
        self.assertIn("Bud1 magic", " ".join(f["evidence"]))

    def test_printable_and_utf16_names_extracted(self):
        f = hit_findings(self.res, path="/.DS_Store")[0]
        joined = " ".join(f["evidence"])
        for name in ("backup.zip", "database.sql", "config_old.php"):
            self.assertIn(name, joined)  # ASCII-stored and UTF-16BE-stored names both found

    def test_typecodes_filtered_and_lossiness_documented(self):
        f = hit_findings(self.res, path="/.DS_Store")[0]
        joined = " ".join(f["evidence"])
        self.assertIn("BEST-EFFORT/LOSSY", joined)
        self.assertIn("not a .DS_Store parser", joined)
        names_line = next(e for e in f["evidence"] if e.startswith("filename-ish strings"))
        for typecode in ("Iloc", "bwsp"):
            self.assertNotIn(typecode, names_line)  # structural tokens never masquerade as names
        self.assertNotIn("Bud1", names_line)  # (the magic legitimately appears in the reason line)

    def test_interesting_filename_grep_applied(self):
        f = hit_findings(self.res, path="/.DS_Store")[0]
        joined = " ".join(f["evidence"])
        self.assertIn("interesting-filename grep", joined)
        self.assertIn("backup.zip", joined)  # matches backup|.zip — the doc's own grep


class TestBatchIsolation(unittest.TestCase):
    """(7) one dead host in a multi-host batch -> captured in errors, rest still processes."""

    def test_dead_host_does_not_kill_the_batch(self):
        fake = FakeHttp()
        fake.error_prefixes.add(DEAD_HOST)
        fake.add(HOST_B + "/.env", 200, ENV_PHRASE_BODY)
        res = sweep(fake, [DEAD_HOST, HOST_B])
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["target"], "batch:2 hosts")
        # dead host: ONE collapsed error line (not 19 identical ones)
        dead_errors = [e for e in res["errors"] if e.startswith(DEAD_HOST)]
        self.assertEqual(len(dead_errors), 1)
        self.assertIn("all %d disclosure-path probe(s) failed" % N_TIER_PATHS, dead_errors[0])
        stats = {h["host"]: h for h in res["metadata"]["hosts"]}
        self.assertEqual(stats[DEAD_HOST]["fetch_errors"], N_TIER_PATHS)
        self.assertEqual(stats[DEAD_HOST]["hits"], 0)
        # living host fully processed despite the dead sibling
        self.assertEqual(stats[HOST_B]["hits"], 1)
        self.assertEqual(len(hit_findings(res, path="/.env")), 1)

    def test_partial_failure_recorded_per_path(self):
        fake = FakeHttp()
        # one transport failure amid otherwise-404 answers -> individual FETCH_FAILED line
        real_fetch = fake.http_fetch

        def flaky(url, timeout, method="GET", extra_headers=None, max_bytes=None):
            if url.endswith("/.env"):
                return _err(url, "socket.timeout: timed out")
            return real_fetch(url, timeout, method, extra_headers, max_bytes)

        with mock.patch.object(es, "http_fetch", flaky):
            res = es.scan_hosts([HOST_A])
        env_errors = [e for e in res["errors"] if "/.env" in e]
        self.assertEqual(len(env_errors), 1)
        self.assertIn("FETCH_FAILED", env_errors[0])
        self.assertEqual(res["metadata"]["hosts"][0]["fetch_errors"], 1)
        self.assertEqual(res["metadata"]["hosts"][0]["misses"], N_TIER_PATHS - 1)


class TestCatchAllGuard(unittest.TestCase):
    """catch-all/soft-200 honesty guard (recon.md §6): root-identical HTML 200s are
    annotated and can never look confirmed; the phrase signal is suppressed on HTML."""

    def test_root_identical_hits_annotated_and_phrase_suppressed(self):
        fake = FakeHttp()
        fake.add(HOST_A + "/", 200, HTML_BODY)
        fake.add(HOST_A + "/.env", 200, HTML_BODY)
        fake.add(HOST_A + "/web.config", 200, HTML_BODY)
        res = sweep(fake, [HOST_A])
        stats = res["metadata"]["hosts"][0]
        self.assertTrue(stats["catch_all_suspect"])
        self.assertEqual(stats["hits"], 2)
        for f in hit_findings(res):
            self.assertEqual(f["severity"], "info")  # html never satisfies a file signature
            self.assertEqual(f["confidence"], es.CONF_BARE_200)
            self.assertIn("catch-all/soft-200", " ".join(f["evidence"]))
        # the run-log mirror flags it too
        self.assertIn("CATCH-ALL SUSPECT", " ".join(res["evidence"]))
        env = hit_findings(res, path="/.env")[0]
        self.assertIn("SUPPRESSED", " ".join(env["evidence"]))  # 'password' in a form is noise
        self.assertNotIn("catch-all indicator phrase", " ".join(env["evidence"]))

    def test_repeat_body_across_three_paths_also_flags(self):
        fake = FakeHttp()
        fake.add(HOST_A + "/.env", 200, HTML_BODY)
        fake.add(HOST_A + "/web.config", 200, HTML_BODY)
        fake.add(HOST_A + "/backup.zip", 200, HTML_BODY)  # root 404s — no root sample
        res = sweep(fake, [HOST_A])
        self.assertTrue(res["metadata"]["hosts"][0]["catch_all_suspect"])
        joined = " ".join(" ".join(f["evidence"]) for f in hit_findings(res))
        self.assertIn("identical body served at 3", joined)


class TestHelpers(unittest.TestCase):
    def test_parse_host(self):
        self.assertEqual(es.parse_host("example.com"), "https://example.com")
        self.assertEqual(es.parse_host("http://example.com:8080/x/y"),
                         "http://example.com:8080")  # path dropped, port kept
        self.assertIsNone(es.parse_host("ftp://example.com"))
        self.assertIsNone(es.parse_host("https://"))

    def test_looks_genuine_ladder_boundary(self):
        self.assertIsNotNone(es.looks_genuine("/.git/HEAD", "0123456789abcdef0123456789abcdef01234567", b"x"))
        self.assertIsNone(es.looks_genuine("/.git/HEAD", "<html>404 page</html>", b"x"))
        self.assertIsNone(es.looks_genuine("/.env", "APP_NAME=demo\n<html><body>x</body></html>", b"x"))
        self.assertIsNotNone(es.looks_genuine("/.env", "A=1\nB=2\n", b"x"))
        self.assertIsNotNone(es.looks_genuine(
            "/appsettings.json", '{"ConnectionStrings": {"Default": "..."}}', b"{}"))
        self.assertIsNone(es.looks_genuine("/appsettings.json", "<html>nope</html>", b"x"))
        self.assertIsNone(es.looks_genuine("/backup.zip", "not a zip", b"PKxx"))
        self.assertIsNone(es.looks_genuine("/backup.zip", "", b"PK\x01\x02junk"))
        self.assertIsNotNone(es.looks_genuine("/backup.zip", "", b"PK\x03\x04rest"))

    def test_redact_remote(self):
        red, cred = es.redact_remote("https://ci-bot:not-a-real-password@example-git.invalid/team.git")
        self.assertTrue(cred)
        self.assertNotIn("not-a-real-password", red)
        self.assertIn("ci-bot:<redacted:19-chars>@example-git.invalid", red)
        plain, cred = es.redact_remote("https://git.internal.example.invalid/team/app.git")
        self.assertFalse(cred)
        self.assertEqual(plain, "https://git.internal.example.invalid/team/app.git")

    def test_extract_git_remotes(self):
        remotes = es.extract_git_remotes(GIT_CONFIG_CREDS.decode())
        self.assertEqual(len(remotes), 1)
        self.assertTrue(remotes[0]["credentialed"])
        # scp-style remote (git@host:path) has no password — never flagged credentialed
        scp = es.extract_git_remotes('url = git@github.example.invalid:org/repo.git\n')
        self.assertFalse(scp[0]["credentialed"])

    def test_extract_dsstore_names_direct(self):
        names = es.extract_dsstore_names(DS_BODY)
        self.assertIn("backup.zip", names)
        self.assertIn("database.sql", names)  # UTF-16BE-stored name found
        self.assertNotIn("Iloc", names)
        self.assertNotIn("bwsp", names)
        self.assertEqual(len(names), len(set(names)))  # deduped

    def test_secret_scan_two_signals(self):
        scan = es.secret_scan(ENV_AWS_BODY.decode())
        self.assertEqual([p["kind"] for p in scan["pattern_hits"]], ["aws_access_key_id"])
        self.assertIn("aws", [p["phrase"] for p in scan["phrase_hits"]])  # separate signal
        html_scan = es.secret_scan(HTML_BODY.decode())
        self.assertEqual(html_scan["pattern_hits"], [])
        self.assertTrue(html_scan["html_body"])
        self.assertEqual([p["phrase"] for p in html_scan["phrase_hits"]], ["password"])


class TestCLIContract(unittest.TestCase):
    """(8) mirrors TestCLIContract from the prior suites; AGGREGATE-not-per-host shape."""

    def test_json_output_shape_and_exit_code(self):
        fake = FakeHttp()
        fake.add(HOST_A + "/.git/HEAD", 200, GIT_HEAD_BODY)
        stdout = io.StringIO()
        with mock.patch.object(es, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stdout(stdout):
            rc = es.main(["--json", "--quiet", HOST_A])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        # ONE aggregate object for the whole batch — never an array of per-host objects
        self.assertIsInstance(payload, dict)
        for key in ("tool", "target", "timestamp", "status", "findings", "evidence",
                    "errors", "metadata"):
            self.assertIn(key, payload)
        self.assertEqual(payload["tool"], "exposure_sweep")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["target"], HOST_A)
        for f in payload["findings"]:
            for key in ("type", "severity", "confidence", "target", "evidence", "source",
                        "next_action"):
                self.assertIn(key, f)
            self.assertEqual(f["type"], "source_disclosure")
            self.assertEqual(f["source"], "exposure_sweep.py")
        h = payload["metadata"]["hosts"][0]
        for key in ("host", "paths_tried", "hits", "misses", "tier1_hits", "tier2_hits",
                    "catch_all_suspect"):
            self.assertIn(key, h)
        self.assertIn("totals", payload["metadata"])
        self.assertIn("tier1_paths", payload["metadata"])
        self.assertIn("tier2_paths", payload["metadata"])

    def test_batch_target_label_and_per_host_stats(self):
        fake = FakeHttp()
        fake.add(HOST_A + "/.env", 200, ENV_PHRASE_BODY)
        fake.add(HOST_B + "/.git/HEAD", 200, GIT_HEAD_BODY)
        stdout = io.StringIO()
        with mock.patch.object(es, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stdout(stdout):
            rc = es.main(["--json", "--quiet", HOST_A, HOST_B])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["target"], "batch:2 hosts")
        self.assertEqual(len(payload["metadata"]["hosts"]), 2)
        self.assertEqual([h["host"] for h in payload["metadata"]["hosts"]], [HOST_A, HOST_B])
        self.assertEqual(len(payload["findings"]), 2)  # aggregate: both hosts' hits in one list

    def test_all_hosts_failed_still_success_exit_zero(self):
        fake = FakeHttp()
        fake.error_prefixes.add(DEAD_HOST)
        stdout = io.StringIO()
        with mock.patch.object(es, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stdout(stdout):
            rc = es.main(["--json", "--quiet", DEAD_HOST])
        self.assertEqual(rc, 0)  # completed scan, not a hard error
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["findings"], [])
        self.assertTrue(payload["errors"])

    def test_hard_errors_exit_nonzero(self):
        fake = FakeHttp()
        with self.assertRaises(SystemExit) as cm:  # no hosts at all -> usage error
            es.main([])
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(es.main(["-l", str(REPO_ROOT / "tests" / "missing-file.txt")]), 2)
        with self.assertRaises(SystemExit) as cm:  # --timeout 0 -> usage error
            es.main([HOST_A, "--timeout", "0"])
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit) as cm:  # --threads 0 -> usage error
            es.main([HOST_A, "--threads", "0"])
        self.assertEqual(cm.exception.code, 2)

    def test_list_file_first_token_and_comments(self):
        # recon/live.txt lines carry $1 = host (recon.md §4d awk '{print $1}') — extra
        # columns (IP etc.) must be ignored
        fake = FakeHttp()
        listfile = REPO_ROOT / "tests" / "fixtures" / "dns" / "exposure_list_smoke.txt"
        listfile.parent.mkdir(parents=True, exist_ok=True)  # a test that needs a fixture dir creates it
        listfile.write_text(
            "# recon/live.txt-style list\n%s 203.0.113.7\n\n# comment\n%s\n"
            % (HOST_A, HOST_B), encoding="utf-8")
        try:
            stdout = io.StringIO()
            with mock.patch.object(es, "http_fetch", fake.http_fetch), \
                 contextlib.redirect_stdout(stdout):
                rc = es.main(["--json", "--quiet", "-l", str(listfile)])
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual([h["host"] for h in payload["metadata"]["hosts"]],
                             [HOST_A, HOST_B])
        finally:
            listfile.unlink()

    def test_human_mode_prints_summary_and_next_hint(self):
        fake = FakeHttp()
        fake.add(HOST_A + "/.git/HEAD", 200, GIT_HEAD_BODY)
        stderr = io.StringIO()
        with mock.patch.object(es, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stderr(stderr), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = es.main([HOST_A])  # no --json/--quiet
        self.assertEqual(rc, 0)
        err = stderr.getvalue()
        self.assertIn(HOST_A, err)
        self.assertIn("LOW/git_head", err)
        self.assertIn("hit(s)", err)
        self.assertIn("Next:", err)
        self.assertIn("validate.md", err)

    def test_output_file_written(self):
        fake = FakeHttp()
        with tempfile.TemporaryDirectory() as td:
            out = str(Path(td) / "exposure.json")
            stderr = io.StringIO()
            with mock.patch.object(es, "http_fetch", fake.http_fetch), \
                 contextlib.redirect_stderr(stderr), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = es.main([HOST_A, "--json", "--output", out])
            self.assertEqual(rc, 0)
            payload = json.loads(Path(out).read_text(encoding="utf-8"))
            self.assertEqual(payload["tool"], "exposure_sweep")

    def test_duplicate_hosts_deduped(self):
        fake = FakeHttp()
        stdout = io.StringIO()
        with mock.patch.object(es, "http_fetch", fake.http_fetch), \
             contextlib.redirect_stdout(stdout):
            rc = es.main(["--json", "--quiet", HOST_A, HOST_A])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(len(payload["metadata"]["hosts"]), 1)
        self.assertEqual(payload["target"], HOST_A)


if __name__ == "__main__":
    unittest.main()
