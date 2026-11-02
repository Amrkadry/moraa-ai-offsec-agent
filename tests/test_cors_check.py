#!/usr/bin/env python3
"""Offline tests for scripts/cors_check.py (TASK-009).

stdlib unittest + unittest.mock only. No real network calls: HTTP is mocked at the module's
single network seam, http_probe — the same testability pattern test_cms_detect.py /
test_js_recon.py / test_subdomain_takeover.py use. Because CORS classification is driven by
RESPONSE HEADERS per Origin (not by body content), the fake routes on the request's Origin
header value instead of the URL path. Decision-table rows from cors.md §1, the §2 bypass
table, the adaptive §2b unescaped-dot trigger, the preflight-consistency check (§2b),
SameSite discipline (§4), per-request error degradation, and the JSON output contract are
all tested offline; the live smoke runs (httpbin.org / .invalid) are a separate verification
step, not part of the suite.

Run:  python3 -m unittest discover -s tests -p "test_cors_check.py" -v
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

import cors_check as cc  # noqa: E402

# fixture host (RFC 6761 reserved .test TLD, like the sibling test files)
TGT = "https://api.fixture-target.test/api/account"
LEGIT_ORIGIN = "https://api.fixture-target.test"
# a dot-1 mutant of api.fixture-target.test ("-" mutation) — used for the §2b hit test
MUTANT_ORIGIN = "https://api-fixture-target.test"


def echo_route(status=200, acac="true", extra=None):
    """Callable route: echoes the request's Origin back in ACAO (the reflection case)."""
    def _route(method, origin):
        headers = {"Access-Control-Allow-Origin": origin}
        if acac is not None:
            headers["Access-Control-Allow-Credentials"] = acac
        headers.update(extra or {})
        return (status, headers, "fixture body")
    return _route


class FakeHttp:
    """Standalone-in for http_probe, routed by Origin header (CORS behavior is per-Origin).
    GET requests use `routes`; OPTIONS preflight requests use `preflight_routes`. A route
    value is a (status, headers, body) tuple, a callable(method, origin) -> tuple, or a
    dict {"error": "..."} for a transport failure. `default` / `preflight_default` answer
    everything unrouted. Every call is recorded as (method, origin)."""

    def __init__(self, routes=None, preflight_routes=None,
                 default=(200, {}, "fixture body"),
                 preflight_default=(200, {}, "fixture body")):
        self.routes = routes or {}
        self.preflight_routes = preflight_routes or {}
        self.default = default
        self.preflight_default = preflight_default
        self.calls = []          # (method, origin)
        self.headers_sent = []   # full header dict per request, for auth-replay assertions

    def _answer(self, table, fallback, method, origin):
        route = table.get(origin, fallback)
        if callable(route):
            route = route(method, origin)   # -> (status, headers, body), normalized below
        if isinstance(route, dict) and "error" in route:
            return {"url": "fixture", "final_url": "fixture", "status": None, "headers": {},
                    "body": None, "set_cookies": [], "error": route["error"], "redirects": []}
        status, headers, body = route
        headers_l = {k.lower(): v for k, v in headers.items()}
        set_cookies = [headers_l.pop("set-cookie")] if "set-cookie" in headers_l else []
        return {"url": "fixture", "final_url": "fixture", "status": status,
                "headers": headers_l, "body": body, "set_cookies": set_cookies,
                "error": None, "redirects": []}

    def http_probe(self, url, timeout, method="GET", extra_headers=None):
        origin = (extra_headers or {}).get("Origin", "")
        self.calls.append((method, origin))
        self.headers_sent.append(dict(extra_headers or {}))
        if method == "OPTIONS":
            return self._answer(self.preflight_routes, self.preflight_default, method, origin)
        return self._answer(self.routes, self.default, method, origin)


def scan(fake, target=TGT, **kwargs):
    """Run scan_target with HTTP fully mocked at http_probe."""
    with mock.patch.object(cc, "http_probe", fake.http_probe):
        return cc.scan_target(target, **kwargs)


def by_name(result):
    return {p["name"]: p for p in result["metadata"]["payload_results"]}


# --------------------------------------------------------------------------
# (1) the cors.md §1 headline: reflection + ACAC:true
# --------------------------------------------------------------------------

class TestReflectedOriginWithCredentials(unittest.TestCase):

    def test_reflected_origin_with_acac_true_is_medium_likely_precondition(self):
        fake = FakeHttp(default=echo_route(acac="true"))
        res = scan(fake)
        f = res["findings"][0]
        self.assertEqual(f["type"], "cors_misconfig")
        self.assertEqual(f["severity"], "medium")          # capped at medium: precondition
        self.assertGreaterEqual(f["confidence"], 0.6)
        self.assertLessEqual(f["confidence"], 0.7)
        self.assertEqual(f["source"], "cors_check.py")
        na = f["next_action"]
        self.assertIn("LIKELY", na)                        # strongest allowed verdict
        self.assertIn("PRECONDITION", na.upper())          # SKILL.md precondition language
        self.assertIn("CONFIRMED", na)                     # ...and why it is never CONFIRMED
        self.assertIn("delivery", na)
        # evidence names real reflected payloads with ACAO/ACAC, not just a verdict
        self.assertTrue(any("ACAC: true" in e and "VULNERABLE-class" in e
                            for e in f["evidence"]))
        # every payload reflected -> stage 2 must NOT run (adaptive, no blind sweep)
        self.assertFalse(res["metadata"]["stage2_dot_sweep"]["triggered"])
        self.assertIn("skipped", res["metadata"]["stage2_dot_sweep"]["reason"])
        pr = by_name(res)
        self.assertTrue(all(p["reflected"] for p in pr.values()))
        self.assertEqual(pr["suffix"]["classification"], "reflected_with_credentials")


# --------------------------------------------------------------------------
# (2) + (3) the special rows of the §1 decision table
# --------------------------------------------------------------------------

class TestDecisionTableSpecialRows(unittest.TestCase):

    def test_wildcard_with_credentials_is_spec_rejected_info_not_exploitable(self):
        fake = FakeHttp(default=(200, {"Access-Control-Allow-Origin": "*",
                                       "Access-Control-Allow-Credentials": "true"}, "x"))
        res = scan(fake)
        f = res["findings"][0]
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["variant"], "wildcard_with_credentials")
        joined = " ".join(f["evidence"]).lower()
        self.assertIn("spec", joined)
        self.assertIn("reject", joined)
        self.assertIn("not exploitable", joined)
        self.assertNotIn("medium", [x["severity"] for x in res["findings"]])
        pr = by_name(res)
        self.assertEqual(pr["arbitrary"]["classification"], "wildcard_with_credentials")

    def test_null_origin_reflected_with_credentials_is_vulnerable_medium(self):
        fake = FakeHttp(routes={"null": echo_route(acac="true")},
                        default=(200, {}, "x"))
        res = scan(fake)
        f = res["findings"][0]
        self.assertEqual(f["severity"], "medium")
        pr = by_name(res)
        self.assertEqual(pr["null"]["classification"], "null_reflected_with_credentials")
        self.assertEqual(pr["arbitrary"]["classification"], "no_acao")
        # §3 primitive named in evidence/next_action: sandboxed data: iframe, no domain needed
        joined = (json.dumps(f["evidence"]) + f["next_action"]).lower()
        self.assertIn("sandboxed", joined)
        self.assertIn("LIKELY", f["next_action"])
        # a null-only hit still means an attacker origin reflected -> stage 2 skipped
        self.assertFalse(res["metadata"]["stage2_dot_sweep"]["triggered"])


# --------------------------------------------------------------------------
# (4) adaptive §2b: fixed allowlist -> dot sweep -> one mutant reflects
# --------------------------------------------------------------------------

class TestUnescapedDotSweep(unittest.TestCase):

    def test_fixed_allowlist_triggers_dot_sweep_and_hit_is_medium_low_confidence(self):
        fake = FakeHttp(
            routes={MUTANT_ORIGIN: echo_route(acac="true")},
            default=(200, {"Access-Control-Allow-Origin": LEGIT_ORIGIN}, "x"))
        res = scan(fake)
        stage2 = res["metadata"]["stage2_dot_sweep"]
        self.assertTrue(stage2["triggered"])
        self.assertEqual(len(stage2["mutants"]), 8)  # 2 dots x 4 chars, deduped
        self.assertEqual(len(stage2["reflecting_with_credentials"]), 1)
        hit = stage2["reflecting_with_credentials"][0]
        self.assertEqual(hit["origin"], MUTANT_ORIGIN)
        self.assertEqual(hit["dot_position"], 1)
        self.assertEqual(hit["char"], "-")
        f = res["findings"][0]
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["variant"], "unescaped_dot_allowlist")
        self.assertGreaterEqual(f["confidence"], 0.4)
        self.assertLessEqual(f["confidence"], 0.5)   # registrability unverified
        na = f["next_action"]
        self.assertIn("RDAP", na)
        self.assertIn("LIKELY", na)
        self.assertIn("unregistered", na.lower())
        self.assertIn("unescaped", " ".join(f["evidence"]).lower())
        # stage-1 payloads were all sent before the sweep (order: sweep is adaptive, not blind)
        self.assertIn(("GET", "https://attacker-controlled.example"), fake.calls)
        self.assertIn(("GET", MUTANT_ORIGIN), fake.calls)

    def test_allowlist_surviving_both_stages_is_info_not_vulnerable(self):
        fake = FakeHttp(default=(200, {"Access-Control-Allow-Origin": LEGIT_ORIGIN}, "x"))
        res = scan(fake)
        f = res["findings"][0]
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["variant"], "not_vulnerable")
        self.assertFalse(any(x["severity"] in ("medium", "low") for x in res["findings"]))
        stage2 = res["metadata"]["stage2_dot_sweep"]
        self.assertTrue(stage2["triggered"])
        self.assertEqual(stage2["reflecting_with_credentials"], [])
        self.assertEqual(len(stage2["mutants"]), 8)
        self.assertIn("survived", " ".join(f["evidence"]))
        # no fabricated escalation; the "tested, not vulnerable" state is explicit
        self.assertIn("Not vulnerable", f["next_action"])
        pr = by_name(res)
        self.assertFalse(any(p["reflected"] for p in pr.values()))


# --------------------------------------------------------------------------
# preflight consistency (cors.md §2b) and SameSite (§4)
# --------------------------------------------------------------------------

class TestPreflightAndSameSite(unittest.TestCase):

    def test_preflight_inconsistency_detected_and_recorded(self):
        suffix = "https://api.fixture-target.test.attacker-controlled.example"
        fake = FakeHttp(
            routes={suffix: echo_route(acac="true")},
            preflight_routes={suffix: (200, {"Access-Control-Allow-Origin": LEGIT_ORIGIN}, "x")},
            default=(200, {}, "x"))
        res = scan(fake)
        pre = res["metadata"]["preflight"]
        self.assertEqual(pre["origin"], suffix)
        self.assertIs(pre["consistent_with_simple"], False)
        self.assertIn("INCONSISTENT", pre["note"])
        self.assertTrue(any("INCONSISTENT" in e and "non-simple verbs" in e
                            for e in res["evidence"]))
        # the GET reflection itself still stands (medium) — preflight only kills other verbs
        self.assertEqual(res["findings"][0]["severity"], "medium")

    def test_preflight_consistent_when_options_honors_the_same_allowlist(self):
        suffix = "https://api.fixture-target.test.attacker-controlled.example"
        fake = FakeHttp(routes={suffix: echo_route(acac="true")},
                        preflight_routes={suffix: echo_route(acac="true")},
                        default=(200, {}, "x"))
        res = scan(fake)
        pre = res["metadata"]["preflight"]
        self.assertIs(pre["consistent_with_simple"], True)
        self.assertIn("honors the same allowlist", pre["note"])

    def test_samesite_parsed_from_baseline_set_cookie_and_folded_in(self):
        fake = FakeHttp(
            routes={"": (200, {"Set-Cookie": "session=fixturevalue; SameSite=Lax; "
                                       "HttpOnly; Path=/"}, "x")},
            default=echo_route(acac="true"))
        res = scan(fake, cookie="session=victimcookievalue")
        ss = res["metadata"]["samesite"]
        self.assertEqual(ss["observed"], "Lax")
        self.assertEqual(ss["cookies"], [{"name": "session", "samesite": "Lax"}])
        # the cookie VALUE never lands in evidence (credentials are not evidence material)
        self.assertNotIn("victimcookievalue", json.dumps(res))
        f = res["findings"][0]
        self.assertEqual(f["severity"], "medium")
        joined = " ".join(f["evidence"])
        self.assertIn("SameSite=Lax", joined)
        self.assertIn("downgraded", joined.lower())
        self.assertIn("same-site", joined.lower())

    def test_samesite_absent_defaults_to_lax_note(self):
        fake = FakeHttp(routes={"": (200, {"Set-Cookie": "session=fixturevalue"}, "x")},
                        default=(200, {"Access-Control-Allow-Origin": "*"}, "x"))
        res = scan(fake)
        ss = res["metadata"]["samesite"]
        self.assertIsNone(ss["observed"])
        self.assertIn("default to Lax", ss["note"])
        self.assertTrue(any("default to Lax" in e for e in res["evidence"]))


# --------------------------------------------------------------------------
# graceful degradation: one bad request never aborts the sweep
# --------------------------------------------------------------------------

class TestDegradation(unittest.TestCase):

    def test_mid_sweep_failure_recorded_and_sweep_completes(self):
        fake = FakeHttp(routes={"https://attacker-controlled.example":
                                {"error": "socket.timeout: timed out"}},
                        default=(200, {}, "x"))
        res = scan(fake)
        pr = by_name(res)
        self.assertEqual(pr["arbitrary"]["classification"], "error")
        self.assertIsNotNone(pr["arbitrary"]["error"])
        self.assertIn("socket.timeout", " ".join(res["errors"]))
        # every payload result is present — the sweep was NOT aborted
        self.assertEqual(len(res["metadata"]["payload_results"]), 14)
        others = [p for n, p in pr.items() if n != "arbitrary"]
        self.assertTrue(all(p["classification"] in ("no_acao", "allowlist_echoed")
                            for p in others))
        self.assertIn(("GET", "https://api.fixture-target.test@attacker-controlled.example"),
                      fake.calls)  # a payload AFTER the failed one was still sent
        # verdict stays honest: clean allowlist, with the failed request noted
        self.assertEqual(res["findings"][0]["variant"], "not_vulnerable")
        self.assertTrue(any("untested this run" in e for e in res["findings"][0]["evidence"]))

    def test_all_transport_failures_are_inconclusive_never_crash(self):
        fake = FakeHttp(default={"error": "URLError: <urlopen error fixture dns failure>"})
        res = scan(fake)
        self.assertEqual(res["status"], "success")
        f = res["findings"][0]
        self.assertEqual(f["severity"], "info")
        self.assertEqual(f["variant"], "unreachable")
        self.assertIn("INCONCLUSIVE", " ".join(f["evidence"]))
        self.assertTrue(len(res["errors"]) >= 1)
        self.assertIn("unreachable", f["next_action"].lower())


# --------------------------------------------------------------------------
# helpers: payload table, dot-mutant loop, classification, SameSite parsing
# --------------------------------------------------------------------------

class TestPayloadTable(unittest.TestCase):

    def test_full_bypass_table_for_https_two_dot_host(self):
        ps = cc.build_origin_payloads("api.fixture-target.test", "https")
        names = [p["name"] for p in ps]
        self.assertEqual(len(names), len(set(names)))
        for expected in ("arbitrary", "suffix", "prefix_raw", "prefix_dashes", "subdomain",
                         "underscore", "underscore_tail", "safari_brace", "safari_brace_close",
                         "safari_backtick", "scheme_downgrade", "userinfo_pass",
                         "userinfo_plain", "null"):
            self.assertIn(expected, names)
        got = {p["name"]: p["origin"] for p in ps}
        a = cc.ATTACKER_PLACEHOLDER
        self.assertEqual(got["arbitrary"], f"https://{a}")
        self.assertEqual(got["suffix"], f"https://api.fixture-target.test.{a}")
        self.assertEqual(got["prefix_raw"], f"https://{a}api.fixture-target.test")
        self.assertEqual(got["subdomain"], f"https://corscheck-probe.api.fixture-target.test")
        self.assertEqual(got["underscore"], f"https://api_fixture-target.test.{a}")
        self.assertEqual(got["underscore_tail"], f"https://api.fixture-target.test_.{a}")
        self.assertEqual(got["safari_brace"], f"https://api.fixture-target.test{{.{a}")
        self.assertEqual(got["safari_brace_close"], f"https://api.fixture-target.test}}.{a}")
        self.assertEqual(got["safari_backtick"], f"https://api.fixture-target.test`.{a}")
        self.assertEqual(got["scheme_downgrade"], "http://api.fixture-target.test")
        self.assertEqual(got["userinfo_pass"], f"https://api.fixture-target.test:evilpass@{a}")
        self.assertEqual(got["userinfo_plain"], f"https://api.fixture-target.test@{a}")
        self.assertEqual(got["null"], "null")
        # the reserved placeholder everywhere — no real registrable attacker domain, ever
        for origin in got.values():
            self.assertNotIn("http://attacker", origin)  # sanity: no accidental real domains

    def test_http_target_omits_scheme_downgrade(self):
        ps = cc.build_origin_payloads("api.fixture-target.test", "http")
        self.assertNotIn("scheme_downgrade", [p["name"] for p in ps])
        self.assertEqual(len(ps), 13)

    def test_dot_mutants_replace_exactly_one_dot_each(self):
        mutants = cc.dot_mutants("api.fixture-target.test")
        self.assertEqual(len(mutants), 8)
        hosts = {m["host"] for m in mutants}
        self.assertIn("api-fixture-target.test", hosts)       # dot 1, "-"
        self.assertIn("api.fixture-targetxtest", hosts)       # dot 2, "x" (cors.md's dfxui shape)
        self.assertIn("apixfixture-target.test", hosts)
        for m in mutants:
            base_dots = "api.fixture-target.test".count(".")
            self.assertEqual(m["host"].count("."), base_dots - 1)  # one dot consumed
            replaced = sum(1 for ch in ("x", "-", "a", "_") if ch in m["host"]
                           and ch not in "api.fixture-target.test")
            self.assertGreaterEqual(replaced, 0)

    def test_dot_mutants_single_dot_host_and_dedup(self):
        mutants = cc.dot_mutants("fixture-target.test")
        self.assertEqual(len(mutants), 4)
        self.assertEqual({m["dot_position"] for m in mutants}, {1})
        # dotless host: nothing to mutate
        self.assertEqual(cc.dot_mutants("localhost"), [])


class TestClassificationAndParsing(unittest.TestCase):

    def test_classify_rows_of_the_decision_table(self):
        self.assertEqual(cc.classify("https://x.example", "https://x.example", "true"),
                         cc.CLASS_VULN)
        self.assertEqual(cc.classify("https://x.example", "https://x.example", "false"),
                         cc.CLASS_NO_CREDS)
        self.assertEqual(cc.classify("https://x.example", "https://x.example", None),
                         cc.CLASS_NO_CREDS)
        self.assertEqual(cc.classify("https://x.example", "*", "true"),
                         cc.CLASS_WILDCARD_CREDS)
        self.assertEqual(cc.classify("https://x.example", "*", None), cc.CLASS_WILDCARD)
        self.assertEqual(cc.classify("null", "null", "true"), cc.CLASS_VULN_NULL)
        self.assertEqual(cc.classify("null", "null", None), cc.CLASS_NULL_NO_CREDS)
        self.assertEqual(cc.classify("https://x.example", None, None), cc.CLASS_NO_ACAO)
        self.assertEqual(cc.classify("https://x.example", LEGIT_ORIGIN, "true"),
                         cc.CLASS_ALLOWLIST)

    def test_raw_regex_acao_is_disclosed_allowlist(self):
        self.assertEqual(cc.classify("https://x.example",
                                     r"^https://[a-z-]+\.fixture-target\.test$", "true"),
                         cc.CLASS_REGEX)
        self.assertTrue(cc.looks_like_regex(r".+\.fixture-target\.test"))
        self.assertFalse(cc.looks_like_regex("https://api.fixture-target.test"))

    def test_parse_samesite(self):
        self.assertEqual(cc.parse_samesite([]), [])
        self.assertEqual(cc.parse_samesite(["sid=abc; SameSite=Lax; HttpOnly"]),
                         [{"name": "sid", "samesite": "Lax"}])
        self.assertEqual(cc.parse_samesite(["sid=abc; samesite=NONE; Secure"]),
                         [{"name": "sid", "samesite": "None"}])
        self.assertEqual(cc.parse_samesite(["sid=abc; Path=/; HttpOnly"]),
                         [{"name": "sid", "samesite": None}])
        self.assertEqual(cc.parse_samesite(["a=1; SameSite=Strict", "b=2"]),
                         [{"name": "a", "samesite": "Strict"}, {"name": "b", "samesite": None}])

    def test_parse_target(self):
        self.assertEqual(cc.parse_target("https://api.fixture-target.test/api"),
                         ("https", "api.fixture-target.test", "https://api.fixture-target.test"))
        self.assertEqual(cc.parse_target("fixture-target.test/api"),
                         ("https", "fixture-target.test", "https://fixture-target.test"))
        self.assertIsNone(cc.parse_target("ftp://fixture-target.test/"))
        self.assertIsNone(cc.parse_target(""))


# --------------------------------------------------------------------------
# (9) CLI / JSON output contract (mirrors the sibling TestCLIContract classes)
# --------------------------------------------------------------------------

class TestCLIContract(unittest.TestCase):

    def test_json_output_shape_and_exit_code(self):
        fake = FakeHttp(default=(200, {"Access-Control-Allow-Origin": "*"}, "x"))
        stdout = io.StringIO()
        with mock.patch.object(cc, "http_probe", fake.http_probe), \
             contextlib.redirect_stdout(stdout):
            rc = cc.main(["--json", "--quiet", TGT])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        for key in ("tool", "target", "timestamp", "status", "findings", "evidence",
                    "errors", "metadata"):
            self.assertIn(key, payload)
        self.assertEqual(payload["tool"], "cors_check")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["target"], TGT)
        f = payload["findings"][0]
        for key in ("type", "severity", "confidence", "target", "evidence", "source",
                    "next_action"):
            self.assertIn(key, f)
        self.assertEqual(f["type"], "cors_misconfig")
        self.assertEqual(f["source"], "cors_check.py")
        # the full sweep is visible in metadata, not just the verdict
        self.assertEqual(payload["metadata"]["legitimate_origin"], LEGIT_ORIGIN)
        self.assertEqual(payload["metadata"]["attacker_placeholder"],
                         "attacker-controlled.example")
        self.assertEqual(len(payload["metadata"]["payload_results"]), 14)
        self.assertIn("samesite", payload["metadata"])
        self.assertIn("preflight", payload["metadata"])
        self.assertIn("stage2_dot_sweep", payload["metadata"])
        self.assertEqual(len(payload["metadata"]["requests_made"]), 16)  # 1+14+1

    def test_cookie_and_header_flags_replay_auth(self):
        fake = FakeHttp(default=(200, {"Access-Control-Allow-Origin": "*"}, "x"))
        stdout = io.StringIO()
        with mock.patch.object(cc, "http_probe", fake.http_probe), \
             contextlib.redirect_stdout(stdout):
            rc = cc.main(["--json", "--quiet", "--cookie", "SESSION=fixture",
                          "--header", "Authorization: Bearer fixture-token", TGT])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["metadata"]["auth_replayed"]["cookie"])
        self.assertEqual([h.lower() for h in payload["metadata"]["auth_replayed"]["headers"]],
                         ["authorization"])
        # preflight advertises the non-safelisted header per cors.md §2b practice — and it
        # actually went out on the wire of the OPTIONS request
        self.assertIn("Authorization",
                      payload["metadata"]["preflight"]["advertised_request_headers"])
        options_sent = [h for (m, o), h in zip(fake.calls, fake.headers_sent) if m == "OPTIONS"]
        self.assertTrue(any(h.get("Authorization") == "Bearer fixture-token"
                            for h in options_sent))

    def test_hard_errors_exit_nonzero(self):
        with self.assertRaises(SystemExit) as cm:  # no targets at all -> usage error
            cc.main([])
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(cc.main(["-l", str(REPO_ROOT / "tests" / "missing-file.txt")]), 2)
        with self.assertRaises(SystemExit) as cm:  # --timeout 0 -> usage error
            cc.main([TGT, "--timeout", "0"])
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit) as cm:  # malformed --header -> usage error
            cc.main([TGT, "--header", "no-colon-here"])
        self.assertEqual(cm.exception.code, 2)

    def test_list_file_targets_processed_in_order(self):
        fake = FakeHttp(default=(200, {"Access-Control-Allow-Origin": "*"}, "x"))
        with tempfile.TemporaryDirectory() as td:
            listfile = Path(td) / "targets.txt"
            listfile.write_text("https://a.fixture-target.test/api\n"
                                "# comment\nhttps://b.fixture-target.test/api\n",
                                encoding="utf-8")
            stdout = io.StringIO()
            with mock.patch.object(cc, "http_probe", fake.http_probe), \
                 contextlib.redirect_stdout(stdout):
                rc = cc.main(["--json", "--quiet", "-l", str(listfile)])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIsInstance(payload, list)
        self.assertEqual([r["target"] for r in payload],
                         ["https://a.fixture-target.test/api",
                          "https://b.fixture-target.test/api"])
        for r in payload:
            self.assertEqual(r["findings"][0]["variant"], "wildcard_public")

    def test_human_mode_prints_summary_and_next_hint(self):
        fake = FakeHttp(default=(200, {"Access-Control-Allow-Origin": "*"}, "x"))
        stderr = io.StringIO()
        with mock.patch.object(cc, "http_probe", fake.http_probe), \
             contextlib.redirect_stderr(stderr), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = cc.main([TGT])  # no --json/--quiet
        self.assertEqual(rc, 0)
        err = stderr.getvalue()
        self.assertIn("INFO", err)
        self.assertIn("Next:", err)
        self.assertIn("precondition", err)

    def test_one_bad_target_never_kills_a_multi_target_run(self):
        # an invalid URL degrades into its own error result; the good target still scans
        fake = FakeHttp(default=(200, {"Access-Control-Allow-Origin": "*"}, "x"))
        stdout = io.StringIO()
        with mock.patch.object(cc, "http_probe", fake.http_probe), \
             contextlib.redirect_stdout(stdout):
            rc = cc.main(["--json", "--quiet", "ftp://fixture-target.test/api", TGT])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(len(payload), 2)
        self.assertEqual(payload[0]["findings"][0]["variant"], "unreachable")
        self.assertTrue(payload[0]["errors"])
        self.assertEqual(payload[1]["findings"][0]["variant"], "wildcard_public")


if __name__ == "__main__":
    unittest.main()
