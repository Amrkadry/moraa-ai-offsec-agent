#!/usr/bin/env python3
"""Offline tests for scripts/github_recon.py (TASK-011).

stdlib unittest + unittest.mock only. NO real network calls and NO real tokens anywhere —
the two external seams this orchestrator has are each mocked separately:

  1. subprocess.run     -> the wrapped tools (trufflehog / gitleaks / github-subdomains)
  2. github_code_search -> the GitHub REST code-search API

Everything else (skip accounting in metadata.sources_skipped, JSONL parsing, gitleaks
report parsing, subdomain line parsing, dork-list construction, rate-limit handling,
token-precedence mirror of lib/config.sh, redaction discipline, CLI contract) is tested
directly. Live no-token smoke runs are a separate verification step, not part of the
suite.

All credential-shaped strings in fixtures are deliberately synthetic (AWS's published
AKIAIOSFODNN7EXAMPLE key plus an explicit not-real suffix, values on RFC 2606 .invalid
hosts) — never real-looking credentials.

Run:  python3 -m unittest discover -s tests -p "test_github_recon.py" -v
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import github_recon as gr  # noqa: E402

ORG = "acme-corp"
DOMAIN = "target.example.invalid"
TOKEN = "ghp_test-token-not-real-1234"
SECRET_RAW = "AKIAIOSFODNN7EXAMPLE-definitely-not-a-real-secret"
GITLEAKS_SECRET = "s3cr3t-value-only-in-fixture-not-real"
DORK_OK = {"ok": True, "status": 200, "rate_limited": False, "error": None,
           "total_count": 0, "items": []}


def trufflehog_jsonl(*objs) -> str:
    return "".join(json.dumps(o) + "\n" for o in objs)


def trufflehog_hit(detector="AWS", verified=True, repo="https://github.com/%s/api" % ORG,
                   file="config/prod_settings.py", line=42, commit="deadbeefcafe",
                   raw=SECRET_RAW):
    return {
        "SourceMetadata": {"Data": {"Git": {"repository": repo, "file": file,
                                            "commit": commit, "line": line}}},
        "SourceID": 1, "SourceType": "Git",
        "DetectorName": detector, "DecoderName": "PLAIN",
        "Verified": verified, "Raw": raw,
    }


GITLEAKS_REPORT = [
    {"RuleID": "generic-api-key", "Description": "Generic API Key",
     "File": "src/settings.py", "StartLine": 17, "Commit": "",
     "Secret": GITLEAKS_SECRET, "Match": "api_key = '%s'" % GITLEAKS_SECRET},
    {"RuleID": "aws-access-token", "Description": "AWS Access Key",
     "File": "docs/example.md", "StartLine": 3, "Commit": "abc123",
     "Secret": "AKIAIOSFODNN7EXAMPLE", "Match": "AKIAIOSFODNN7EXAMPLE"},
]

SUBS_STDOUT = ("api.%s\n"
               "internal-jira.%s\n"
               "\n"
               "total 42 found by github-subdomains\n"   # banner line: dropped, counted
               "api.%s\n" % (DOMAIN, DOMAIN, DOMAIN))    # duplicate: deduped


def dork_item(repo="acme-corp/api", path="config/settings.json", name="settings.json"):
    return {"name": name, "path": path,
            "html_url": "https://github.com/%s/blob/main/%s" % (repo, path),
            "repository": {"full_name": repo}}


class FakeCompleted:
    def __init__(self, rc=0, out="", err=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


class FakeTools:
    """Standalone-in for subprocess.run. Handlers keyed by tool basename; the gitleaks
    handler writes its JSON report before returning (the real tool's contract). Every
    call's argv is recorded so tests can assert the exact wrapped-CLI syntax."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.handlers = {}   # basename -> fn(argv) -> FakeCompleted (or raises)

    def run(self, argv, capture_output=False, text=False, timeout=None):
        argv = list(argv)
        self.calls.append(argv)
        handler = self.handlers.get(Path(argv[0]).name)
        if handler is None:   # unexpected tool invocation: loud, not silently clean
            return FakeCompleted(rc=99, err="FakeTools: no handler for %s" % argv[0])
        return handler(argv)


class FakeSearch:
    """Standalone-in for github_code_search. Routes queries to full result dicts;
    unrouted queries answer a clean empty search."""

    def __init__(self, routes=None):
        self.calls: list[str] = []
        self.routes = dict(routes or {})

    def search(self, query, token, timeout):
        self.calls.append(query)
        return self.routes.get(query, dict(DORK_OK))


def no_token_env():
    """Env with GH_TOKEN/MORAA_CONFIG_FILE scrubbed (config pointed at a missing file)
    so tests are independent of any real token on the machine."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("GH_TOKEN", "MORAA_CONFIG_FILE")}
    env["MORAA_CONFIG_FILE"] = str(REPO_ROOT / "tests" / "no-such-config.json")
    return env


def run_main(argv, token=None, tools=None, handlers=None, search=None):
    """Run gr.main under the fully patched world.
      tools:    basename -> path for find_tool (absent = not installed)
      handlers: basename -> fn(argv) -> FakeCompleted for subprocess.run
      search:   query -> result dict (plus FakeSearch default)
    Returns (rc, stdout, stderr, fake_tools, fake_search)."""
    ft, fs = FakeTools(), FakeSearch(search)
    ft.handlers.update(handlers or {})
    env = no_token_env()
    if token:
        env["GH_TOKEN"] = token

    def finder(name):
        return (tools or {}).get(name)

    stdout, stderr = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch.object(gr, "find_tool", side_effect=finder), \
         mock.patch.object(gr.subprocess, "run", ft.run), \
         mock.patch.object(gr, "github_code_search", fs.search), \
         mock.patch.object(gr.time, "sleep"), \
         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = gr.main(argv)
    return rc, stdout.getvalue(), stderr.getvalue(), ft, fs


def scan_direct(tools=None, handlers=None, search=None, token=TOKEN, **kwargs):
    """scan_github directly (sleep_s forced to 0); returns (result, fake_tools,
    fake_search). Tools default to ALL ABSENT so only the dork sweep can run."""
    ft, fs = FakeTools(), FakeSearch(search)
    ft.handlers.update(handlers or {})
    env = no_token_env()
    if token:
        env["GH_TOKEN"] = token
    with mock.patch.dict(os.environ, env, clear=True), \
         mock.patch.object(gr, "find_tool", side_effect=lambda n: (tools or {}).get(n)), \
         mock.patch.object(gr.subprocess, "run", ft.run), \
         mock.patch.object(gr, "github_code_search", fs.search), \
         mock.patch.object(gr.time, "sleep"):
        res = gr.scan_github(sleep_s=0, token=token, token_source="test", **kwargs)
    return res, ft, fs


def skipped_map(payload):
    return {s["source"]: s["reason"] for s in payload["metadata"]["sources_skipped"]}


def secret_hits(payload, tool=None):
    out = [f for f in payload["findings"] if f["type"] == "github_secret_hit"]
    return [f for f in out if tool is None or f.get("tool") == tool]


# --------------------------------------------------------------------------
# (1) every source skipped -> still a clean success with explicit reasons
# --------------------------------------------------------------------------

class TestAllSourcesSkipped(unittest.TestCase):

    def test_no_tools_no_token_all_four_skipped_with_reasons(self):
        rc, out, _, _, _ = run_main(["--org", ORG, "--domain", DOMAIN, "--json",
                                     "--quiet"], token=None, tools={})
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "success")
        skipped = skipped_map(payload)
        self.assertEqual(set(skipped), set(gr.SOURCE_NAMES))
        for reason in skipped.values():
            self.assertTrue(reason.strip())
        self.assertIn("not installed", skipped["trufflehog"])
        self.assertIn("not installed", skipped["gitleaks"])
        self.assertIn("not installed", skipped["github-subdomains"])
        self.assertIn("unauthenticated code search returns ZERO results",
                      skipped["github_dork_sweep"])
        self.assertEqual(payload["metadata"]["sources_run"], [])

    def test_all_tools_present_no_token_still_all_skipped_token_reasons(self):
        all_tools = {n: "/fake/bin/" + n for n in gr.SOURCE_NAMES if n != "github_dork_sweep"}
        rc, out, _, ft, _ = run_main(["--org", ORG, "--domain", DOMAIN, "--json",
                                      "--quiet"], token=None, tools=all_tools)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        skipped = skipped_map(payload)
        self.assertEqual(set(skipped), set(gr.SOURCE_NAMES))
        # tools ARE present, so the reasons must say WHY they didn't run (no token /
        # no local-repo) — never a vague "not found"
        self.assertIn("no GH_TOKEN", skipped["trufflehog"])
        self.assertIn("--local-repo not given", skipped["gitleaks"])
        self.assertIn("never clones", skipped["gitleaks"])   # scope boundary is stated
        self.assertIn("no GH_TOKEN", skipped["github-subdomains"])
        self.assertIn("no GH_TOKEN", skipped["github_dork_sweep"])
        self.assertEqual(ft.calls, [])                       # no tool was ever invoked

    def test_tool_and_token_but_no_org_trufflehog_skipped_not_run(self):
        rc, out, _, ft, _ = run_main(["--domain", DOMAIN, "--json", "--quiet"],
                                     token=TOKEN, tools={n: "/fake/bin/" + n
                                                         for n in ("trufflehog",)})
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        skipped = skipped_map(payload)
        self.assertIn("--org not given", skipped["trufflehog"])
        self.assertEqual(ft.calls, [])
        self.assertNotIn("trufflehog", payload["metadata"]["sources_run"])


# --------------------------------------------------------------------------
# (2) THE money test: trufflehog VERIFIED -> high, raw secret NEVER in output
# --------------------------------------------------------------------------

class TestTrufflehogVerified(unittest.TestCase):

    def setUp(self):
        self.handlers = {
            "trufflehog": lambda a: FakeCompleted(
                rc=0, out=trufflehog_jsonl(trufflehog_hit(verified=True)), err="")}

    def test_verified_hit_high_and_raw_secret_nowhere_in_output(self):
        rc, out, _, _, _ = run_main(
            ["--org", ORG, "--json", "--quiet"], token=TOKEN,
            tools={"trufflehog": "/fake/bin/trufflehog"}, handlers=self.handlers)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        hits = secret_hits(payload)
        self.assertEqual(len(hits), 1)
        f = hits[0]
        self.assertEqual(f["severity"], "high")
        self.assertIs(f["verified"], True)
        self.assertEqual(f["detector"], "AWS")
        self.assertIn("VERIFIED LIVE", " ".join(f["evidence"]))
        self.assertIn("config/prod_settings.py", f["target"])
        self.assertIn("rotate", f["next_action"].lower())
        # the redaction contract, checked over the ENTIRE serialized result — the raw
        # value must appear nowhere in any finding/evidence/error/metadata field
        self.assertNotIn(SECRET_RAW, out)
        self.assertNotIn(SECRET_RAW, json.dumps(payload))

    def test_exact_trufflehog_cli_syntax(self):
        handlers = {"trufflehog": lambda a: FakeCompleted(rc=0, out="", err="")}
        rc, _, _, ft, _ = run_main(["--org", ORG, "--json", "--quiet"], token=TOKEN,
                                   tools={"trufflehog": "/fake/bin/trufflehog"},
                                   handlers=handlers)
        self.assertEqual(rc, 0)
        (argv,) = ft.calls   # exactly one tool invocation
        self.assertEqual(Path(argv[0]).name, "trufflehog")
        self.assertIn("github", argv)
        self.assertIn("--org=%s" % ORG, argv)
        self.assertIn("--json", argv)
        self.assertIn("--token=%s" % TOKEN, argv)
        self.assertIn("--results=verified,unverified", argv)
        self.assertNotIn("--no-verification", argv)   # verification stays ON: the point

    def test_rc_nonzero_with_partial_stdout_still_parses_streamed_hits(self):
        handlers = {"trufflehog": lambda a: FakeCompleted(
            rc=3, out=trufflehog_jsonl(trufflehog_hit(verified=True)),
            err="some repo clone failed")}
        rc, out, _, _, _ = run_main(["--org", ORG, "--json", "--quiet"], token=TOKEN,
                                    tools={"trufflehog": "/fake/bin/trufflehog"},
                                    handlers=handlers)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(len(secret_hits(payload)), 1)
        self.assertTrue(any("trufflehog" in e and "rc=3" in e
                            for e in payload["errors"]))
        self.assertNotIn(SECRET_RAW, out)


# --------------------------------------------------------------------------
# (3) unverified trufflehog hit -> medium + "not live-verified" language
# --------------------------------------------------------------------------

class TestTrufflehogUnverified(unittest.TestCase):

    def test_unverified_hit_medium_not_live_verified_language(self):
        handlers = {"trufflehog": lambda a: FakeCompleted(
            rc=0, out=trufflehog_jsonl(trufflehog_hit(verified=False)), err="")}
        rc, out, _, _, _ = run_main(["--org", ORG, "--json", "--quiet"], token=TOKEN,
                                    tools={"trufflehog": "/fake/bin/trufflehog"},
                                    handlers=handlers)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        hits = secret_hits(payload)
        self.assertEqual(len(hits), 1)
        f = hits[0]
        self.assertEqual(f["severity"], "medium")
        self.assertIs(f["verified"], False)
        joined = " ".join(f["evidence"])
        self.assertIn("NOT live-verified", joined)
        self.assertIn("confirm before reporting", joined)
        self.assertNotIn(SECRET_RAW, out)


# --------------------------------------------------------------------------
# (4)/(5) gitleaks: skipped without --local-repo; parsed with it
# --------------------------------------------------------------------------

class TestGitleaks(unittest.TestCase):

    def test_skipped_without_local_repo_with_reason(self):
        rc, out, _, ft, _ = run_main(["--org", ORG, "--json", "--quiet"], token=TOKEN,
                                     tools={"gitleaks": "/fake/bin/gitleaks"})
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        skipped = skipped_map(payload)
        self.assertIn("gitleaks", skipped)
        self.assertIn("--local-repo not given", skipped["gitleaks"])
        self.assertIn("never clones", skipped["gitleaks"])
        self.assertNotIn("gitleaks", payload["metadata"]["sources_run"])
        self.assertNotIn("gitleaks", [Path(c[0]).name for c in ft.calls])

    def test_invoked_with_local_repo_parses_report(self):
        self_handlers = {
            "github-subdomains": lambda a: FakeCompleted(rc=0, out="", err=""),
            "gitleaks": lambda a: (
                Path(a[a.index("--report-path") + 1]).write_text(
                    json.dumps(GITLEAKS_REPORT), encoding="utf-8"),
                FakeCompleted(rc=1, out="", err=""))[1],  # rc=1 = leaks found: expected
        }
        with tempfile.TemporaryDirectory() as td:
            rc, out, _, ft, _ = run_main(
                ["--local-repo", td, "--domain", DOMAIN, "--json", "--quiet"],
                token=TOKEN,
                tools={n: "/fake/bin/" + n for n in ("gitleaks", "github-subdomains")},
                handlers=self_handlers)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertIn("gitleaks", payload["metadata"]["sources_run"])
        leaks = secret_hits(payload, tool="gitleaks")
        self.assertEqual(len(leaks), 2)
        for f in leaks:
            self.assertEqual(f["severity"], "medium")   # gitleaks = NOT live-verified
            self.assertIs(f["verified"], False)
            self.assertIn("NOT live-verified", " ".join(f["evidence"]))
        self.assertNotIn(GITLEAKS_SECRET, out)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        gargv = [c for c in ft.calls if Path(c[0]).name == "gitleaks"][0]
        self.assertIn("detect", gargv)
        self.assertIn("--no-git", gargv)
        self.assertIn("-s", gargv)
        self.assertIn("--report-format", gargv)
        self.assertIn("json", gargv)
        self.assertIn("--report-path", gargv)
        self.assertEqual(payload["metadata"]["gitleaks_local_repo"], td)

    def test_rc1_without_report_file_is_error_not_crash(self):
        handlers = {"gitleaks": lambda a: FakeCompleted(rc=1, out="", err="")}
        with tempfile.TemporaryDirectory() as td:
            rc, out, _, _, _ = run_main(["--local-repo", td, "--domain", DOMAIN,
                                         "--json", "--quiet"], token=TOKEN,
                                        tools={"gitleaks": "/fake/bin/gitleaks"},
                                        handlers=handlers)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "success")
        self.assertTrue(payload["errors"])   # missing report -> honest error entry
        self.assertEqual(secret_hits(payload), [])


# --------------------------------------------------------------------------
# (6) github-subdomains -> info summary finding + metadata.subdomains_found
# --------------------------------------------------------------------------

class TestGithubSubdomains(unittest.TestCase):

    def test_stdout_parsed_into_summary_and_metadata(self):
        handlers = {"github-subdomains": lambda a: FakeCompleted(rc=0, out=SUBS_STDOUT,
                                                                 err="")}
        rc, out, _, ft, _ = run_main(["--domain", DOMAIN, "--json", "--quiet"],
                                     token=TOKEN,
                                     tools={"github-subdomains":
                                            "/fake/bin/github-subdomains"},
                                     handlers=handlers)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        sums = [f for f in payload["findings"]
                if f["type"] == "github_subdomain_summary"]
        self.assertEqual(len(sums), 1)
        f = sums[0]
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["subdomains_found"],
                         ["api." + DOMAIN, "internal-jira." + DOMAIN])
        self.assertEqual(payload["metadata"]["subdomains_found"], f["subdomains_found"])
        self.assertNotIn(TOKEN, out)
        sargv = [c for c in ft.calls if Path(c[0]).name == "github-subdomains"][0]
        self.assertEqual(sargv[1:], ["-d", DOMAIN, "-t", TOKEN, "-raw"])
        self.assertTrue(sargv[0].endswith("github-subdomains"))

    def test_failed_run_never_emits_fake_clean_summary(self):
        handlers = {"github-subdomains": lambda a: FakeCompleted(rc=7, out="", err="boom")}
        rc, out, _, _, _ = run_main(["--domain", DOMAIN, "--json", "--quiet"],
                                    token=TOKEN,
                                    tools={"github-subdomains":
                                           "/fake/bin/github-subdomains"},
                                    handlers=handlers)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual([f for f in payload["findings"]
                          if f["type"] == "github_subdomain_summary"], [])
        self.assertTrue(payload["errors"])
        self.assertEqual(payload["metadata"]["subdomains_found"], [])


# --------------------------------------------------------------------------
# (7) dork sweep: hits -> low findings; 403/422 -> recorded, sweep continues
# --------------------------------------------------------------------------

class TestDorkSweep(unittest.TestCase):

    def test_hits_become_low_findings_with_repo_path_name(self):
        q = '"%s" AKIA' % DOMAIN
        res, _, fs = scan_direct(
            search={q: {"ok": True, "status": 200, "rate_limited": False, "error": None,
                        "total_count": 2,
                        "items": [dork_item(), dork_item(repo="acme-corp/cli",
                                                         path="scripts/deploy.sh",
                                                         name="deploy.sh")]}},
            org=None, domain=DOMAIN)
        hits = [f for f in res["findings"] if f["type"] == "github_dork_hit"]
        self.assertEqual(len(hits), 1)
        f = hits[0]
        self.assertEqual(f["severity"], "low")
        self.assertEqual(f["target"], q)
        self.assertEqual(len(f["hits"]), 2)
        self.assertEqual(f["hits"][0]["repo"], "acme-corp/api")
        self.assertEqual(f["hits"][0]["path"], "config/settings.json")
        self.assertIn("manually open", f["next_action"])
        self.assertIn(q, fs.calls)                          # the routed dork was queried
        self.assertEqual(len(fs.calls), 6)                  # every scoped dork queried
        self.assertEqual(len(res["metadata"]["dorks"]), 6)  # domain-only -> 6 dorks built
        self.assertEqual(res["metadata"]["totals"]["dork_hits"], 2)
        self.assertNotIn(TOKEN, json.dumps(res))

    def test_zero_hit_dorks_recorded_as_ran_clean(self):
        res, _, _ = scan_direct(org=ORG)
        self.assertEqual([f for f in res["findings"] if f["type"] == "github_dork_hit"], [])
        self.assertEqual({d["status"] for d in res["metadata"]["dorks"]}, {"ok"})
        self.assertEqual(len(res["metadata"]["dorks"]), 2)   # org-only -> 2 dorks
        self.assertTrue(any("0 hits" in e for e in res["evidence"]))

    def test_rate_limited_dork_recorded_and_sweep_continues(self):
        pwq = ('org:%s "password"|"secret"|"api_key"|"apikey"|"token"|'
               '"BEGIN RSA PRIVATE KEY"' % ORG)
        awsq = 'org:%s language:yaml "aws_secret_access_key"' % ORG
        limited = {"ok": False, "status": 403, "rate_limited": True,
                   "error": "HTTP 403: rate limit exceeded", "items": [], "total_count": 0}

        real = FakeSearch({awsq: {"ok": True, "status": 200, "rate_limited": False,
                                  "error": None, "total_count": 1,
                                  "items": [dork_item()]}}).search

        def flaky(query, token, timeout):
            if query == pwq:
                return limited
            return real(query, token, timeout)

        env = no_token_env()
        env["GH_TOKEN"] = TOKEN
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(gr, "find_tool", side_effect=lambda n: None), \
             mock.patch.object(gr, "github_code_search", flaky), \
             mock.patch.object(gr.time, "sleep"):
            res = gr.scan_github(org=ORG, token=TOKEN, token_source="test", sleep_s=0)

        self.assertEqual(res["metadata"]["rate_limited_dorks"], [pwq])
        stats = {d["query"]: d["status"] for d in res["metadata"]["dorks"]}
        self.assertEqual(stats[pwq], "rate_limited")
        self.assertEqual(stats[awsq], "ok")              # sweep CONTINUED after the 403
        dork_hits = [f for f in res["findings"] if f["type"] == "github_dork_hit"]
        self.assertEqual(len(dork_hits), 1)              # the post-403 dork still landed
        self.assertTrue(any("RATE-LIMITED" in e for e in res["evidence"]))
        self.assertEqual(res["status"], "success")

    def test_422_treated_as_rate_limited_too(self):
        res, _, _ = scan_direct(search={
            '"%s" AKIA' % DOMAIN: {"ok": False, "status": 422, "rate_limited": True,
                                   "error": "HTTP 422", "items": [], "total_count": 0}},
            org=None, domain=DOMAIN)
        self.assertEqual(res["metadata"]["rate_limited_dorks"], ['"%s" AKIA' % DOMAIN])
        self.assertEqual(res["metadata"]["totals"]["dorks_rate_limited"], 1)

    def test_dork_list_matches_recon_md_section4(self):
        both = gr.build_dorks(ORG, DOMAIN)
        self.assertEqual(len(both), 8)
        self.assertEqual(both[0], 'org:%s "password"|"secret"|"api_key"|"apikey"|"token"|'
                                  '"BEGIN RSA PRIVATE KEY"' % ORG)
        self.assertEqual(both[-1], 'org:%s language:yaml "aws_secret_access_key"' % ORG)
        self.assertIn('"%s" AKIA' % DOMAIN, both)
        self.assertIn('"%s" password' % DOMAIN, both)
        self.assertIn('"%s" filename:.env' % DOMAIN, both)
        self.assertIn('"%s" filename:config extension:json' % DOMAIN, both)
        self.assertIn('"%s" "authorization: bearer"' % DOMAIN, both)
        self.assertIn('"internal" "%s" filename:.npmrc' % DOMAIN, both)
        self.assertEqual(len(gr.build_dorks(ORG, None)), 2)
        self.assertEqual(len(gr.build_dorks(None, DOMAIN)), 6)


# --------------------------------------------------------------------------
# (8) one source's subprocess failure never kills the run
# --------------------------------------------------------------------------

class TestSubprocessFailureIsolation(unittest.TestCase):

    def test_trufflehog_crash_others_still_complete(self):
        handlers = {
            "trufflehog": lambda a: FakeCompleted(rc=1, out="", err="fatal: exploded"),
            "github-subdomains": lambda a: FakeCompleted(rc=0, out="x." + DOMAIN + "\n",
                                                         err=""),
        }
        all_tools = {n: "/fake/bin/" + n
                     for n in ("trufflehog", "github-subdomains")}
        rc, out, _, _, _ = run_main(["--org", ORG, "--domain", DOMAIN, "--json",
                                     "--quiet"], token=TOKEN, tools=all_tools,
                                    handlers=handlers)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "success")
        self.assertTrue(any("trufflehog" in e for e in payload["errors"]))
        runs = payload["metadata"]["sources_run"]
        self.assertIn("trufflehog", runs)           # attempted...
        self.assertIn("github-subdomains", runs)    # ...and the others still completed
        self.assertIn("github_dork_sweep", runs)
        self.assertTrue(any(f["type"] == "github_subdomain_summary"
                            for f in payload["findings"]))

    def test_trufflehog_timeout_recorded_no_fabricated_findings(self):
        def timeout_handler(argv):
            raise subprocess.TimeoutExpired(cmd="trufflehog", timeout=900,
                                            output=trufflehog_jsonl(
                                                trufflehog_hit(verified=True)))
        rc, out, _, _, _ = run_main(["--org", ORG, "--json", "--quiet"], token=TOKEN,
                                    tools={"trufflehog": "/fake/bin/trufflehog"},
                                    handlers={"trufflehog": timeout_handler})
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertTrue(any("TOOL_TIMEOUT" in e for e in payload["errors"]))
        # a truncated-after-timeout JSONL stream must NOT be parsed into findings —
        # the honest outcome is the error entry and zero secret hits
        self.assertEqual(secret_hits(payload), [])

    def test_unparseable_trufflehog_line_counted_not_fatal(self):
        handlers = {"trufflehog": lambda a: FakeCompleted(
            rc=0, out="this-is-not-json\n" + trufflehog_jsonl(
                trufflehog_hit(verified=False)), err="")}
        rc, out, _, _, _ = run_main(["--org", ORG, "--json", "--quiet"], token=TOKEN,
                                    tools={"trufflehog": "/fake/bin/trufflehog"},
                                    handlers=handlers)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(len(secret_hits(payload)), 1)
        self.assertTrue(any("unparseable" in e for e in payload["evidence"]))


# --------------------------------------------------------------------------
# token resolution — python mirror of lib/config.sh moraa_config_get
# --------------------------------------------------------------------------

class TestTokenResolution(unittest.TestCase):

    def test_cli_beats_env_beats_config(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            cfg.write_text(json.dumps({"GH_TOKEN": "cfg-token"}), encoding="utf-8")
            env = no_token_env()
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(gr.get_github_token("cli-tok"), ("cli-tok", "cli"))
                self.assertEqual(gr.get_github_token(None), (None, None))
            env["MORAA_CONFIG_FILE"] = str(cfg)
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(gr.get_github_token(None), ("cfg-token", "config-file"))
                env["GH_TOKEN"] = "env-token"
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(gr.get_github_token(None), ("env-token", "env"))

    def test_config_file_missing_or_broken_is_none_not_crash(self):
        env = no_token_env()
        env["MORAA_CONFIG_FILE"] = str(REPO_ROOT / "tests" / "definitely-missing.json")
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(gr.get_github_token(None), (None, None))
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "broken.json"
            bad.write_text("{not json", encoding="utf-8")
            env["MORAA_CONFIG_FILE"] = str(bad)
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(gr.get_github_token(None), (None, None))

    def test_real_config_json_path_used_when_no_override(self):
        with tempfile.TemporaryDirectory() as td:
            fake_home = Path(td) / "home"
            (fake_home / ".moraa").mkdir(parents=True)
            (fake_home / ".moraa" / "config.json").write_text(
                json.dumps({"GH_TOKEN": "home-token"}), encoding="utf-8")
            env = no_token_env()
            del env["MORAA_CONFIG_FILE"]
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(gr.Path, "home", return_value=fake_home):
                self.assertEqual(gr.get_github_token(None), ("home-token", "config-file"))


# --------------------------------------------------------------------------
# helpers + redaction safety net
# --------------------------------------------------------------------------

class TestHelpers(unittest.TestCase):

    def test_make_scrubber(self):
        s = gr.make_scrubber("abc-secret-value", "tok123")
        self.assertEqual(s("found abc-secret-value here"),
                         "found <redacted:16-chars> here")
        self.assertEqual(s("tok123 also gone"), "<redacted:6-chars> also gone")
        self.assertEqual(s("untouched"), "untouched")

    def test_parse_subdomain_lines_drops_banners_and_dedupes(self):
        subs, dropped = gr.parse_subdomain_lines(SUBS_STDOUT)
        self.assertEqual(subs, ["api." + DOMAIN, "internal-jira." + DOMAIN])
        self.assertEqual(dropped, 1)

    def test_parse_trufflehog_jsonl(self):
        objs, bad = gr.parse_trufflehog_jsonl(
            trufflehog_jsonl(trufflehog_hit(), trufflehog_hit()) + "\nnot json\n")
        self.assertEqual(len(objs), 2)
        self.assertEqual(bad, 1)

    def test_parse_gitleaks_report_shapes(self):
        with tempfile.TemporaryDirectory() as td:
            p = str(Path(td) / "r.json")
            Path(p).write_text(json.dumps(GITLEAKS_REPORT), encoding="utf-8")
            self.assertEqual(len(gr.parse_gitleaks_report(p)), 2)
            Path(p).write_text(json.dumps({"findings": GITLEAKS_REPORT}),
                               encoding="utf-8")
            self.assertEqual(len(gr.parse_gitleaks_report(p)), 2)
            Path(p).write_text("nope", encoding="utf-8")
            self.assertEqual(gr.parse_gitleaks_report(p), [])
            self.assertEqual(gr.parse_gitleaks_report(str(Path(td) / "missing.json")), [])

    def test_trufflehog_gitmeta_defensive(self):
        self.assertEqual(gr._trufflehog_gitmeta({}), {})
        self.assertEqual(gr._trufflehog_gitmeta({"SourceMetadata": None}), {})
        flat = {"SourceMetadata": {"Data": {"file": "x.py"}}}
        self.assertEqual(gr._trufflehog_gitmeta(flat).get("file"), "x.py")
        nested = {"SourceMetadata": {"Data": {"Git": {"repository": "r", "line": 9}}}}
        self.assertEqual(gr._trufflehog_gitmeta(nested).get("line"), 9)

    def test_secret_hit_finding_shape_verified_vs_not(self):
        scrub = gr.make_scrubber("")
        hi = gr._secret_hit_finding("trufflehog", "AWS", True, "repo", "f.py", 3, "abc",
                                    scrub)
        self.assertEqual(hi["severity"], "high")
        med = gr._secret_hit_finding("gitleaks", "rule", False, "repo", "f.py", 3, "",
                                     scrub)
        self.assertEqual(med["severity"], "medium")
        for f in (hi, med):
            for key in ("type", "severity", "confidence", "target", "evidence",
                        "source", "next_action"):
                self.assertIn(key, f)
        self.assertNotIn("Raw", json.dumps([hi, med]))

    def test_run_tool_timeout_and_oserror_are_soft(self):
        def boom(argv, capture_output, text, timeout):
            raise subprocess.TimeoutExpired(cmd="x", timeout=1)
        with mock.patch.object(gr.subprocess, "run", boom):
            rc, o, e = gr.run_tool(["x"], 1.0)
        self.assertIsNone(rc)
        self.assertIn("TOOL_TIMEOUT", e)
        with mock.patch.object(gr.subprocess, "run",
                               side_effect=OSError("spawn failed")):
            rc, o, e = gr.run_tool(["x"], 1.0)
        self.assertIsNone(rc)
        self.assertIn("OSError", e)


# --------------------------------------------------------------------------
# (9) CLI/JSON output contract
# --------------------------------------------------------------------------

class TestCLIContract(unittest.TestCase):

    def test_json_output_shape_and_exit_code(self):
        rc, out, _, _, _ = run_main(["--org", ORG, "--domain", DOMAIN, "--json",
                                     "--quiet"], token=None, tools={})
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertIsInstance(payload, dict)
        for key in ("tool", "target", "timestamp", "status", "findings", "evidence",
                    "errors", "metadata"):
            self.assertIn(key, payload)
        self.assertEqual(payload["tool"], "github_recon")
        self.assertEqual(payload["status"], "success")
        self.assertIn("org:%s" % ORG, payload["target"])
        self.assertIn("domain:%s" % DOMAIN, payload["target"])
        for f in payload["findings"]:
            for key in ("type", "severity", "confidence", "target", "evidence",
                        "source", "next_action"):
                self.assertIn(key, f)
            self.assertEqual(f["source"], "github_recon.py")
        md = payload["metadata"]
        for key in ("org", "domain", "token_source", "sources_run", "sources_skipped",
                    "dorks", "rate_limited_dorks", "subdomains_found",
                    "gitleaks_local_repo", "trufflehog_verification", "timeout_api_s",
                    "timeout_tool_s", "totals"):
            self.assertIn(key, md)
        for s in md["sources_skipped"]:
            self.assertEqual(set(s), {"source", "reason"})
        self.assertIsNone(md["token_source"])   # no token -> presence recorded as None

    def test_token_source_recorded_but_never_the_value(self):
        rc, out, _, _, _ = run_main(["--org", ORG, "--json", "--quiet"], token=TOKEN,
                                    tools={})
        payload = json.loads(out)
        self.assertEqual(payload["metadata"]["token_source"], "env")
        self.assertNotIn(TOKEN, out)

    def test_no_org_no_domain_is_hard_error(self):
        with self.assertRaises(SystemExit) as cm:
            run_main(["--json", "--quiet"])
        self.assertEqual(cm.exception.code, 2)

    def test_bad_timeout_is_hard_error(self):
        with self.assertRaises(SystemExit) as cm:
            run_main(["--org", ORG, "--timeout", "0", "--json", "--quiet"])
        self.assertEqual(cm.exception.code, 2)

    def test_local_repo_missing_is_hard_error_rc2(self):
        rc, _, _, _, _ = run_main(["--org", ORG, "--local-repo", "/no/such/dir",
                                   "--json", "--quiet"], token=None, tools={})
        self.assertEqual(rc, 2)

    def test_output_file_written(self):
        with tempfile.TemporaryDirectory() as td:
            out_path = str(Path(td) / "gh.json")
            rc, _, _, _, _ = run_main(["--org", ORG, "--json", "--output", out_path],
                                      token=None, tools={})
            self.assertEqual(rc, 0)
            payload = json.loads(Path(out_path).read_text(encoding="utf-8"))
            self.assertEqual(payload["tool"], "github_recon")

    def test_human_mode_shows_skips_and_next_hint(self):
        rc, out, err, _, _ = run_main(["--org", ORG], token=None, tools={})
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "")          # machine output ONLY with --json
        self.assertIn("[skip] trufflehog", err)
        self.assertIn("[skip] gitleaks", err)
        self.assertIn("[skip] github_dork_sweep", err)
        self.assertIn("Next:", err)
        self.assertIn("coverage.md", err)

    def test_token_never_printed_even_when_tool_echoes_argv(self):
        handlers = {"trufflehog": lambda a: FakeCompleted(
            rc=2, out="", err="usage: trufflehog github --org=<ORG> --token=%s" % TOKEN)}
        rc, out, err, _, _ = run_main(["--org", ORG, "--json", "--verbose"], token=TOKEN,
                                      tools={"trufflehog": "/fake/bin/trufflehog"},
                                      handlers=handlers)
        self.assertEqual(rc, 0)
        self.assertNotIn(TOKEN, out)
        self.assertNotIn(TOKEN, err)
        payload = json.loads(out)
        self.assertNotIn(TOKEN, json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
