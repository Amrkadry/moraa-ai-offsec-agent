#!/usr/bin/env python3
"""Offline tests for scripts/graphql_recon.py (TASK-015).

stdlib unittest + unittest.mock only. No real network calls and no real GraphQL
server: HTTP is mocked at the module's single network seam, probe_http (the
cms_detect.py house pattern). The fake is BODY-AWARE where the tests need it —
GraphQL requests are distinguished by the query document they carry ({__typename}
discovery, __schema introspection, my_alias bypass, bare {word} fallback probes) —
which is exactly the seam the real pipeline reasons about. Pipeline logic, the
disabled-vs-auth distinction, the aliased bypass, suggestion parsing, boundedness,
multi-target degradation, and the JSON output contract are all tested offline; live
smoke runs (api.github.com as a negative target / .invalid) are a separate
verification step, not part of the suite.

Run:  python3 -m unittest discover -s tests -p "test_graphql_recon.py" -v
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

import graphql_recon as gr  # noqa: E402

BLOCKED_MSG = "GraphQL introspection is not allowed by Apollo GraphQL Studio (fixture)"
AUTH_MSG = "Your session does not permit access to this operation (fixture auth)"


def make_schema():
    """Fixture schema: 4 named types, 4 root fields, 3 sensitive-name fields."""
    return {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {"name": "Query", "fields": [
                {"name": "user", "args": [{"name": "id", "type": {"name": "ID"}}],
                 "type": {"name": "User"}},
                {"name": "apiSecretKey", "args": [], "type": {"name": "String"}},
                {"name": "orders", "args": [], "type": {"name": "[Order]"}},
            ]},
            {"name": "Mutation", "fields": [
                {"name": "updateUser",
                 "args": [{"name": "input", "type": {"name": "UserInput"}}],
                 "type": {"name": "User"}},
            ]},
            {"name": "User", "fields": [
                {"name": "passwordHash", "args": [], "type": {"name": "String"}},
                {"name": "email", "args": [], "type": {"name": "String"}},
            ]},
            {"name": "String", "fields": None},
        ],
    }


def gql(payload, status=200):
    return (status, {"Content-Type": "application/json"}, json.dumps(payload))


def gerr(message, status=200):
    return (status, {"Content-Type": "application/json"},
            json.dumps({"errors": [{"message": message}]}))


def make_live_handler(schema=None, plain_blocked=False, alias_succeeds=False,
                      auth_message=None, suggestion_map=None):
    """Body-aware handler for one live GraphQL endpoint. Routes on the query document:
    {__typename} / __schema introspection / my_alias bypass / bare {word} fallback
    probes — the same distinctions the real pipeline makes."""
    schema = schema if schema is not None else make_schema()
    suggestion_map = suggestion_map or {}

    def handler(body):
        q = body.get("query", "")
        if q == "{__typename}":
            if auth_message:
                return gerr(auth_message)
            return gql({"data": {"__typename": "Query"}})
        if "my_alias" in q:
            if alias_succeeds:
                return gql({"data": {"my_alias": schema}})
            return gerr(auth_message or BLOCKED_MSG)
        if "__schema" in q:
            if plain_blocked or auth_message:
                return gerr(auth_message or BLOCKED_MSG)
            return gql({"data": {"__schema": schema}})
        m = re.fullmatch(r"\{(\w+)\}", q)
        word = m.group(1) if m else ""
        if auth_message:
            return gerr(auth_message)
        for w, sugg in suggestion_map.items():
            if word == w:
                quoted = ", ".join('"%s"' % s for s in sugg)
                return gerr('Cannot query field "%s" on type "Query". Did you mean %s?'
                            % (word, quoted))
        return gerr('Cannot query field "%s" on type "Query".' % word)

    return handler


class FakeHttp:
    """Standalone-in for probe_http, routes by URL path; a route value may be a
    (status, headers, body) tuple or a callable(request_body_dict) -> tuple. A host in
    error_hosts simulates transport failure on every request. Records every call as
    'METHOD path' plus the parsed request bodies for boundedness assertions."""

    def __init__(self, routes=None, default=None, error_hosts=None):
        self.routes = routes or {}
        self.default = default or (404, {"Content-Type": "text/html"}, "File not found.")
        self.error_hosts = error_hosts or {}
        self.calls: list[str] = []
        self.bodies: list[dict] = []

    def probe_http(self, url, timeout, data=None):
        parts = urllib.parse.urlsplit(url)
        try:
            body = json.loads(data.decode("utf-8")) if data else {}
        except (ValueError, UnicodeDecodeError):
            body = {}
        self.calls.append(("POST" if data is not None else "GET") + " " + parts.path)
        self.bodies.append(body)
        if parts.netloc in self.error_hosts:
            return {"url": url, "final_url": url, "status": None, "headers": {},
                    "body": None, "error": self.error_hosts[parts.netloc], "redirects": []}
        route = self.routes.get(parts.path, self.default)
        if callable(route):
            route = route(body)
        if isinstance(route, dict) and "error" in route:
            return {"url": url, "final_url": url, "status": None, "headers": {},
                    "body": None, "error": route["error"], "redirects": []}
        status, headers, resp_body = route
        return {"url": url, "final_url": url, "status": status,
                "headers": {k.lower(): v for k, v in headers.items()},
                "body": resp_body, "error": None, "redirects": []}


def scan(fake, target, all_paths=False, timeout=5.0):
    with mock.patch.object(gr, "probe_http", fake.probe_http):
        return gr.scan_target(target, timeout=timeout, all_paths=all_paths)


def bare_word_bodies(fake):
    """Request bodies of the fallback stage: bare {word} probes minus {__typename}."""
    out = []
    for b in fake.bodies:
        q = b.get("query", "")
        m = re.fullmatch(r"\{(\w+)\}", q)
        if m and m.group(1) != "__typename":
            out.append(m.group(1))
    return out


# ---------------------------------------------------------------------------
# (1) no endpoint found -> clean negative, success status, exit 0
# ---------------------------------------------------------------------------

class TestNoEndpoint(unittest.TestCase):
    def test_clean_negative_result(self):
        # default = generic 404 HTML everywhere; /api/graphql answers with a
        # REST-shaped JSON error — NOT GraphQL-shaped (no top-level data/errors key)
        fake = FakeHttp(routes={"/api/graphql": (200, {"Content-Type": "application/json"},
                                                 json.dumps({"message": "Not Found"}))})
        res = scan(fake, "fixture-none.test")
        self.assertEqual(res["tool"], "graphql_recon")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["metadata"]["endpoint_found"], None)
        self.assertEqual(res["metadata"]["introspection_status"],
                         "not-applicable-no-endpoint")
        self.assertIsNone(res["metadata"]["type_count"])
        # all 8 doc paths probed (https base answered, no http fallback)
        self.assertEqual(len(res["metadata"]["path_probes"]), len(gr.GRAPHQL_PATHS))
        self.assertFalse(res["metadata"]["fallback"]["ran"])
        self.assertEqual(res["errors"], [])
        # the REST-shaped JSON page was probed and correctly rejected
        self.assertIn("POST /api/graphql", fake.calls)

    def test_negative_via_main_exit_zero(self):
        fake = FakeHttp()
        stdout = io.StringIO()
        with mock.patch.object(gr, "probe_http", fake.probe_http), \
             contextlib.redirect_stdout(stdout):
            rc = gr.main(["--json", "--quiet", "fixture-none.test"])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["metadata"]["introspection_status"],
                         "not-applicable-no-endpoint")


# ---------------------------------------------------------------------------
# (2) endpoint at a non-default path; probing stops at the first hit
# ---------------------------------------------------------------------------

class TestEndpointDiscovery(unittest.TestCase):
    def test_found_at_api_graphql_and_stops_early(self):
        fake = FakeHttp(routes={"/api/graphql": make_live_handler()})
        res = scan(fake, "fixture-api.test")
        md = res["metadata"]
        self.assertEqual(md["endpoint_found"], "https://fixture-api.test/api/graphql")
        self.assertIn("POST /graphql", fake.calls)          # probed, missed (404)
        self.assertIn("POST /api/graphql", fake.calls)      # probed, HIT
        self.assertNotIn("POST /v1/graphql", fake.calls)    # stopped after the hit
        self.assertNotIn("POST /query", fake.calls)
        ep = res["findings"][0]
        self.assertEqual(ep["type"], "graphql_endpoint_discovered")
        self.assertEqual(ep["severity"], "info")
        self.assertEqual(ep["source"], "graphql_recon.py")
        self.assertTrue(any("GraphQL-shaped" in e for e in ep["evidence"]))

    def test_caller_supplied_path_probed_verbatim(self):
        fake = FakeHttp(routes={"/internal/gql": make_live_handler()})
        res = scan(fake, "https://fixture-path.test/internal/gql")
        self.assertEqual(res["metadata"]["endpoint_found"],
                         "https://fixture-path.test/internal/gql")
        self.assertEqual(fake.calls[0], "POST /internal/gql")
        # no doc-list path was probed at all: the caller's own path hit immediately
        for p in gr.GRAPHQL_PATHS:
            self.assertNotIn("POST " + p, fake.calls)

    def test_scheme_fallback_to_http_when_https_dead(self):
        fake = FakeHttp(routes={"/graphql": make_live_handler()},
                        error_hosts={})  # https:// and http:// both hit /graphql
        calls = []

        def probe(url, timeout, data=None):
            calls.append(url)
            if url.startswith("https://"):
                return {"url": url, "final_url": url, "status": None, "headers": {},
                        "body": None, "error": "URLError: refused", "redirects": []}
            return fake.probe_http(url, timeout, data=data)

        with mock.patch.object(gr, "probe_http", probe):
            res = gr.scan_target("fixture-scheme.test", timeout=5.0)
        self.assertEqual(res["metadata"]["endpoint_found"],
                         "http://fixture-scheme.test/graphql")


# ---------------------------------------------------------------------------
# (3) introspection succeeds -> schema summary + sensitive-field findings
# ---------------------------------------------------------------------------

class TestIntrospectionSuccess(unittest.TestCase):
    def setUp(self):
        self.fake = FakeHttp(routes={"/graphql": make_live_handler()})
        self.res = scan(self.fake, "fixture-live.test")

    def test_schema_summary_counts(self):
        md = self.res["metadata"]
        self.assertEqual(md["introspection_status"], "enabled")
        self.assertEqual(md["type_count"], 4)
        self.assertEqual(md["root_field_count"], 4)
        self.assertEqual(md["root_types"], ["Query", "Mutation"])
        self.assertIn("user(id: ID) -> User",
                      " ".join(e for e in self.res["evidence"]))

    def test_schema_exposed_is_info_with_root_fields_in_evidence(self):
        schema_f = next(f for f in self.res["findings"]
                        if f["type"] == "graphql_schema_exposed")
        self.assertEqual(schema_f["severity"], "info")
        self.assertGreater(schema_f["confidence"], 0.9)
        self.assertTrue(any("apiSecretKey" in e for e in schema_f["evidence"]))
        self.assertIn("two accounts", schema_f["next_action"])

    def test_sensitive_fields_get_own_low_findings(self):
        sens = [f for f in self.res["findings"]
                if f["type"] == "graphql_sensitive_field_flagged"]
        self.assertEqual(len(sens), 3)
        for f in sens:
            self.assertEqual(f["severity"], "low")
            self.assertIn("two accounts", f["next_action"])
            self.assertIn("not a finding", f["next_action"])
        names = {f["field"] for f in sens}
        self.assertEqual(names, {"Query.apiSecretKey", "User.passwordHash", "User.email"})
        self.assertEqual(sorted(self.res["metadata"]["sensitive_fields_flagged"]),
                         sorted(names))

    def test_fallback_not_run_when_introspection_enabled(self):
        self.assertFalse(self.res["metadata"]["fallback"]["ran"])
        # discovery + introspection only — no wordlist probes
        self.assertEqual(len(self.fake.calls), 2)
        self.assertEqual(self.res["metadata"]["requests_made"], 2)


# ---------------------------------------------------------------------------
# (4) plain __schema blocked but {__typename} answers -> "disabled", aliased retry
# ---------------------------------------------------------------------------

class TestIntrospectionDisabledDistinction(unittest.TestCase):
    def setUp(self):
        # plain AND aliased both blocked; endpoint itself alive
        self.fake = FakeHttp(routes={"/graphql": make_live_handler(plain_blocked=True,
                                                                   alias_succeeds=False,
                                                                   suggestion_map={})})
        self.res = scan(self.fake, "fixture-blocked.test")

    def test_distinguished_as_disabled_not_auth(self):
        self.assertEqual(self.res["metadata"]["introspection_status"], "disabled")
        self.assertTrue(any("{__typename} still answers" in e
                            for e in self.res["evidence"]))
        self.assertNotIn("auth-required", json.dumps(self.res["metadata"]))

    def test_aliased_retry_was_sent(self):
        alias_bodies = [b for b in self.fake.bodies if "my_alias" in b.get("query", "")]
        self.assertEqual(len(alias_bodies), 1)
        self.assertIn("__schema", alias_bodies[0]["query"])
        self.assertTrue(any("aliased bypass also failed" in e
                            for e in self.res["evidence"]))

    def test_falls_through_to_fallback(self):
        self.assertTrue(self.res["metadata"]["fallback"]["ran"])
        self.assertEqual(self.res["metadata"]["fallback"]["probes_sent"],
                         len(gr.FIELD_WORDLIST))


# ---------------------------------------------------------------------------
# (5) aliased bypass succeeds -> low bypass finding + recovered schema
# ---------------------------------------------------------------------------

class TestAliasedBypass(unittest.TestCase):
    def setUp(self):
        self.fake = FakeHttp(routes={"/graphql": make_live_handler(plain_blocked=True,
                                                                   alias_succeeds=True)})
        self.res = scan(self.fake, "fixture-waf.test")

    def test_status_and_low_bypass_finding(self):
        self.assertEqual(self.res["metadata"]["introspection_status"],
                         "blocked-retried-aliased-succeeded")
        bypass = next(f for f in self.res["findings"]
                      if f["type"] == "graphql_introspection_bypass")
        self.assertEqual(bypass["severity"], "low")
        self.assertIn("my_alias: __schema", " ".join(bypass["evidence"]))
        self.assertIn("WAF", bypass["next_action"] + " ".join(bypass["evidence"]))
        self.assertTrue(any("aliased bypass SUCCEEDED" in e
                            for e in self.res["evidence"]))

    def test_recovered_schema_reported(self):
        self.assertEqual(self.res["metadata"]["type_count"], 4)
        self.assertEqual(self.res["metadata"]["root_field_count"], 4)
        schema_f = next(f for f in self.res["findings"]
                        if f["type"] == "graphql_schema_exposed")
        self.assertEqual(schema_f["severity"], "info")

    def test_no_fallback_when_bypass_recovered_schema(self):
        self.assertFalse(self.res["metadata"]["fallback"]["ran"])
        word_probes = [b for b in self.fake.bodies
                       if re.fullmatch(r"\{(\w+)\}", b.get("query", ""))
                       and b["query"] != "{__typename}"]
        self.assertEqual(word_probes, [])


# ---------------------------------------------------------------------------
# (6) fully disabled -> bounded field-suggestion fallback, suggestions captured
# ---------------------------------------------------------------------------

class TestFieldSuggestionFallback(unittest.TestCase):
    def setUp(self):
        self.fake = FakeHttp(routes={"/graphql": make_live_handler(
            plain_blocked=True, alias_succeeds=False,
            suggestion_map={"user": ["users", "userId"],
                            "config": ["configs", "appConfig"]})})
        self.res = scan(self.fake, "fixture-suggest.test")

    def test_suggestion_leak_finding_is_info_and_mentions_clairvoyance(self):
        leak = next(f for f in self.res["findings"]
                    if f["type"] == "graphql_field_suggestion_leak")
        self.assertEqual(leak["severity"], "info")
        joined = json.dumps(leak)
        self.assertIn("clairvoyance", joined)
        self.assertIn("users", joined)
        self.assertIn("configs", joined)
        # suggestions are labeled as server-suggested (real schema names)
        self.assertTrue(any('suggested "users"' in e for e in leak["evidence"]))

    def test_websocket_note_present_when_introspection_fully_blocked(self):
        ep = next(f for f in self.res["findings"]
                  if f["type"] == "graphql_endpoint_discovered")
        self.assertIn("websocket.md", ep["next_action"])
        leak = next(f for f in self.res["findings"]
                    if f["type"] == "graphql_field_suggestion_leak")
        self.assertIn("websocket.md", leak["next_action"])

    def test_bounded_exactly_one_probe_per_wordlist_entry(self):
        words = bare_word_bodies(self.fake)
        self.assertEqual(len(words), len(gr.FIELD_WORDLIST))
        self.assertEqual(len(words), len(set(words)))
        self.assertEqual(self.res["metadata"]["fallback"]["probes_sent"],
                         len(gr.FIELD_WORDLIST))

    def test_no_signal_no_finding(self):
        fake = FakeHttp(routes={"/graphql": make_live_handler(plain_blocked=True,
                                                              suggestion_map={})})
        res = scan(fake, "fixture-quiet.test")
        self.assertTrue(res["metadata"]["fallback"]["ran"])
        self.assertEqual([f for f in res["findings"]
                          if f["type"] == "graphql_field_suggestion_leak"], [])


# ---------------------------------------------------------------------------
# (7) auth-required: {__typename} fails too -> no fallback garbage
# ---------------------------------------------------------------------------

class TestAuthRequired(unittest.TestCase):
    def test_distinguished_from_disabled_and_fallback_skipped(self):
        fake = FakeHttp(routes={"/graphql": make_live_handler(auth_message=AUTH_MSG)})
        res = scan(fake, "fixture-auth.test")
        self.assertEqual(res["metadata"]["introspection_status"], "auth-required")
        self.assertTrue(any("requires auth" in e for e in res["evidence"]))
        self.assertFalse(res["metadata"]["fallback"]["ran"])
        # discovery + introspection + {__typename} liveness probe = exactly 3;
        # the aliased retry is NOT sent (endpoint is not confirmed alive)
        self.assertEqual(len(fake.calls), 3)
        self.assertFalse(any("my_alias" in b.get("query", "") for b in fake.bodies))
        ep = res["findings"][0]
        self.assertIn("authenticated session", ep["next_action"])


# ---------------------------------------------------------------------------
# --all-paths: opt-in exhaustive endpoint enumeration
# ---------------------------------------------------------------------------

class TestAllPathsMode(unittest.TestCase):
    def setUp(self):
        self.routes = {"/graphql": make_live_handler(),
                       "/query": make_live_handler()}

    def test_default_stops_at_first_hit(self):
        fake = FakeHttp(routes=self.routes)
        res = scan(fake, "fixture-multi.test")
        self.assertEqual(res["metadata"]["endpoint_found"],
                         "https://fixture-multi.test/graphql")
        self.assertEqual(res["metadata"]["additional_endpoints"], [])
        self.assertNotIn("POST /query", fake.calls)
        self.assertEqual(len([f for f in res["findings"]
                              if f["type"] == "graphql_endpoint_discovered"]), 1)

    def test_all_paths_enumerates_and_introspects_every_endpoint(self):
        fake = FakeHttp(routes=self.routes)
        res = scan(fake, "fixture-multi.test", all_paths=True)
        self.assertIn("POST /query", fake.calls)
        self.assertEqual(res["metadata"]["additional_endpoints"],
                         ["https://fixture-multi.test/query"])
        self.assertEqual(len([f for f in res["findings"]
                              if f["type"] == "graphql_endpoint_discovered"]), 2)
        self.assertEqual(len(res["metadata"]["per_endpoint"]), 2)
        self.assertEqual(res["metadata"]["introspection_status"], "enabled")


# ---------------------------------------------------------------------------
# multi-target batch: one dead target captured, the rest still processed
# ---------------------------------------------------------------------------

class TestMultiTargetDegradation(unittest.TestCase):
    def test_dead_target_in_batch_never_kills_the_run(self):
        fake = FakeHttp(routes={"/graphql": make_live_handler()},
                        error_hosts={"dead.test": "URLError: fixture resolution failure"})
        stdout = io.StringIO()
        with mock.patch.object(gr, "probe_http", fake.probe_http), \
             contextlib.redirect_stdout(stdout):
            rc = gr.main(["--json", "--quiet", "dead.test", "live.test"])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIsInstance(payload, list)
        self.assertEqual([r["target"] for r in payload], ["dead.test", "live.test"])
        dead, live = payload
        self.assertEqual(dead["status"], "success")   # a dead target is a valid result
        self.assertEqual(dead["findings"], [])
        self.assertTrue(dead["errors"])
        self.assertTrue(all("dead.test" in e or e.startswith("...")
                            for e in dead["errors"]))
        self.assertEqual(live["metadata"]["endpoint_found"],
                         "https://live.test/graphql")
        # dead target error list is capped, never an unbounded dump
        self.assertLessEqual(len(dead["errors"]), gr.MAX_ERRORS + 1)


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------

class TestHelpers(unittest.TestCase):
    def test_is_graphql_shape(self):
        self.assertTrue(gr.is_graphql_shape({"data": {"__typename": "Query"}}))
        self.assertTrue(gr.is_graphql_shape({"errors": [{"message": "x"}]}))
        self.assertFalse(gr.is_graphql_shape({"message": "Not Found"}))  # REST-shaped
        self.assertFalse(gr.is_graphql_shape("not a dict"))
        self.assertFalse(gr.is_graphql_shape([1, 2, 3]))
        self.assertFalse(gr.is_graphql_shape({}))

    def test_extract_schema_plain_and_aliased(self):
        self.assertEqual(gr.extract_schema({"data": {"__schema": {"a": 1}}}), {"a": 1})
        self.assertEqual(gr.extract_schema({"data": {"my_alias": {"a": 1}}}), {"a": 1})
        self.assertIsNone(gr.extract_schema({"data": {"__schema": None}}))
        self.assertIsNone(gr.extract_schema({"errors": []}))
        self.assertIsNone(gr.extract_schema(None))

    def test_parse_did_you_mean_variants(self):
        self.assertEqual(gr.parse_did_you_mean(
            'Cannot query field "usr" on type "Query". Did you mean "user" or "users"?'),
            ["user", "users"])
        self.assertEqual(gr.parse_did_you_mean('Did you mean "users { ... }"?'), [])
        self.assertEqual(gr.parse_did_you_mean('nothing to see here'), [])

    def test_render_field_and_type_labels(self):
        f = {"name": "orders", "args": [{"name": "limit", "type": {"name": "Int"}}],
             "type": {"name": None, "kind": "LIST", "ofType": {"name": "Order"}}}
        self.assertEqual(gr.render_field(f), "orders(limit: Int) -> [Order]")
        self.assertEqual(gr._type_label({"name": None}), "?")

    def test_summarize_schema_heuristic_roots_without_pointers(self):
        s = gr.summarize_schema({"types": [
            {"name": "query_root", "fields": [
                {"name": "row", "args": [], "type": {"name": "Row"}}]}]})
        self.assertEqual(s["root_types"], ["query_root"])
        self.assertEqual(s["root_field_count"], 1)

    def test_summarize_schema_sensitive_dedupe(self):
        s = gr.summarize_schema({"queryType": {"name": "Query"}, "types": [
            {"name": "Query", "fields": [
                {"name": "apiKey", "args": [], "type": {"name": "String"}},
                {"name": "apiKey", "args": [], "type": {"name": "String"}}]},
            {"name": "Other", "fields": [
                {"name": "apiKey", "args": [], "type": {"name": "String"}}]}]})
        self.assertEqual(s["sensitive_fields"], ["Query.apiKey", "Other.apiKey"])

    def test_collapse_errors_dedupes_and_caps(self):
        errs = [f"POST https://t/{i}: boom" for i in range(20)] + ["POST https://t/0: boom"]
        out = gr._collapse_errors(errs)
        self.assertEqual(len(out), gr.MAX_ERRORS + 1)
        self.assertIn("suppressed", out[-1])
        self.assertEqual(gr._collapse_errors(["same", "same"]), ["same"])

    def test_wordlist_bounded_generic_and_unique(self):
        wl = gr.FIELD_WORDLIST
        self.assertGreaterEqual(len(wl), 100)
        self.assertLessEqual(len(wl), 150)
        self.assertEqual(len(wl), len(set(wl)))
        for mandated in ("id", "user", "users", "me", "viewer", "node", "account",
                         "accounts", "admin", "config", "settings", "search", "query",
                         "list", "get", "create", "update", "delete", "login", "logout",
                         "auth", "token", "session", "profile", "order", "orders",
                         "product", "products", "payment", "transaction", "balance",
                         "transfer", "health", "status", "version", "__type"):
            self.assertIn(mandated, wl)
        for w in wl:  # generic API-shaped identifiers only
            self.assertRegex(w, r"^[A-Za-z_][A-Za-z0-9_]*$")

    def test_sensitive_regex_matches_task_pattern(self):
        for name in ("apiSecretKey", "passwordHash", "accessToken", "ssn", "creditCard",
                     "userEmail", "isAdmin", "internalNote", "debugFlag", "userRole",
                     "hasPermission", "credit_card_number"):
            self.assertTrue(gr.SENSITIVE_RE.search(name), name)
        for name in ("orders", "viewer", "updateUser", "cart"):
            self.assertFalse(gr.SENSITIVE_RE.search(name), name)

    def test_path_candidates(self):
        paths, own = gr.path_candidates("fixture.test")
        self.assertEqual(paths, gr.GRAPHQL_PATHS)
        self.assertEqual(own, "")
        paths, own = gr.path_candidates("https://t.test/api")
        self.assertEqual(paths[0], "/api")
        self.assertIn("/graphql", paths)
        paths, own = gr.path_candidates("https://t.test/graphql")
        self.assertEqual(paths, gr.GRAPHQL_PATHS)  # deduped, own == /graphql

    def test_normalize_target(self):
        self.assertEqual(gr.normalize_target("t.test"),
                         ["https://t.test", "http://t.test"])
        self.assertEqual(gr.normalize_target("https://t.test/"), ["https://t.test"])


# ---------------------------------------------------------------------------
# CLI / JSON output contract
# ---------------------------------------------------------------------------

class TestCLIContract(unittest.TestCase):
    def test_json_output_shape_and_exit_code(self):
        fake = FakeHttp(routes={"/graphql": make_live_handler()})
        stdout = io.StringIO()
        with mock.patch.object(gr, "probe_http", fake.probe_http), \
             contextlib.redirect_stdout(stdout):
            rc = gr.main(["--json", "--quiet", "fixture-wp.test"])
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        for key in ("tool", "target", "timestamp", "status", "findings", "evidence",
                    "errors", "metadata"):
            self.assertIn(key, payload)
        self.assertEqual(payload["tool"], "graphql_recon")
        self.assertEqual(payload["status"], "success")
        md = payload["metadata"]
        for key in ("endpoint_found", "introspection_status", "type_count",
                    "root_field_count", "sensitive_fields_flagged", "path_probes",
                    "fallback", "requests_made"):
            self.assertIn(key, md)
        for f in payload["findings"]:
            for key in ("type", "severity", "confidence", "target", "evidence",
                        "source", "next_action"):
                self.assertIn(key, f)
            self.assertEqual(f["source"], "graphql_recon.py")
        self.assertEqual(payload["findings"][0]["type"], "graphql_endpoint_discovered")

    def test_hard_errors_exit_nonzero(self):
        with self.assertRaises(SystemExit) as cm:  # no targets at all -> usage error
            gr.main([])
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(gr.main(["-l", str(REPO_ROOT / "tests" / "missing-file.txt")]), 2)
        with self.assertRaises(SystemExit) as cm:  # --timeout 0 -> usage error
            gr.main(["t.test", "--timeout", "0"])
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit) as cm:  # --threads 0 -> usage error
            gr.main(["t.test", "--threads", "0"])
        self.assertEqual(cm.exception.code, 2)

    def test_list_file_targets_processed_in_order(self):
        listfile = REPO_ROOT / "tests" / "fixtures" / "graphql" / "list_smoke.txt"
        listfile.parent.mkdir(parents=True, exist_ok=True)
        listfile.write_text("https://a.test/\n# comment\nb.test\n", encoding="utf-8")
        try:
            fake = FakeHttp()  # default 404: no endpoint anywhere
            stdout = io.StringIO()
            with mock.patch.object(gr, "probe_http", fake.probe_http), \
                 contextlib.redirect_stdout(stdout):
                rc = gr.main(["--json", "--quiet", "-l", str(listfile)])
            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertIsInstance(payload, list)
            self.assertEqual([r["target"] for r in payload],
                             ["https://a.test/", "b.test"])
            for r in payload:
                self.assertEqual(r["findings"], [])
        finally:
            listfile.unlink()  # self-cleaning (TASK-013 lesson)

    def test_human_mode_prints_summary_and_next_hint(self):
        fake = FakeHttp(routes={"/graphql": make_live_handler()})
        stderr = io.StringIO()
        with mock.patch.object(gr, "probe_http", fake.probe_http), \
             contextlib.redirect_stderr(stderr), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = gr.main(["fixture-human.test"])  # no --json/--quiet
        self.assertEqual(rc, 0)
        err = stderr.getvalue()
        self.assertIn("GraphQL endpoint", err)
        self.assertIn("introspection: enabled", err)
        self.assertIn("Next:", err)

    def test_human_mode_negative_result(self):
        fake = FakeHttp()
        stderr = io.StringIO()
        with mock.patch.object(gr, "probe_http", fake.probe_http), \
             contextlib.redirect_stderr(stderr), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = gr.main(["fixture-empty.test"])
        self.assertEqual(rc, 0)
        self.assertIn("no GraphQL endpoint found", stderr.getvalue())
        self.assertIn("Next:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
