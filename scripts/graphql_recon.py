#!/usr/bin/env python3
"""graphql_recon.py — GraphQL endpoint discovery + introspection dump + bounded
field-suggestion fallback (graphql.md's "Discover & map" section, automated; TASK-015).

WHY: graphql.md opens with a hand-run curl loop (find the endpoint, fire the
introspection query, fall back to "did you mean" error mining) — pure recon done
ad hoc today, exactly the gap js_recon.py filled for JS mining. This script makes it
one bounded, evidence-logging call per target. It is deliberately a RECON/MAPPING
tool, not an exploitation tool: it discovers the endpoint, dumps or reconstructs the
schema, and flags what is WORTH testing by hand. It never attempts the IDOR /
mass-assignment / alias-batching-brute attacks graphql.md documents — those need two
real accounts and human judgment (graphql.md's own Method section).

Pipeline (per target):

    TARGET -> ENDPOINT DISCOVERY: POST {"query":"{__typename}"} (Content-Type:
              application/json) to graphql.md's exact path list — /graphql,
              /api/graphql, /v1/graphql, /graphql/console, /graphiql, /playground,
              /query, /gql — plus the caller's own path verbatim when the target URL
              carries one. A response confirms a GraphQL endpoint only when the body
              parses as JSON with a top-level "data" or "errors" key (GraphQL's own
              response shape) — a generic 404/HTML page is not a hit even when it
              returns 200. Bounded: stops at the first confirmed endpoint unless
              --all-paths (some apps expose several GraphQL endpoints for different
              services — opt-in exhaustive mode).
           -> INTROSPECTION: the full __schema query (graphql.md's exact query, plus
              queryType/mutationType/subscriptionType{name} so root fields can be
              attributed deterministically instead of by name-guessing). On failure
              the script DISTINGUISHES "introspection disabled" from "endpoint
              requires auth" by re-probing {__typename} on the SAME endpoint: if the
              trivial query still answers, the endpoint is live and it is the
              __schema keyword that is blocked -> one aliased-bypass retry using
              graphql.md's documented technique (wrap __schema in an alias —
              `query { my_alias: __schema {...} }` — which dodges WAF/middleware
              rules matching the bare-keyword query pattern). If {__typename} fails
              too, the endpoint requires auth and introspection availability is
              simply unknown (no fallback garbage is generated).
           -> FIELD-SUGGESTION FALLBACK (Clairvoyance-style, BOUNDED): only when
              introspection is genuinely disabled, probe the root Query type with a
              ~140-entry wordlist of generic API-shaped field names — ONE request per
              word, ~140 total, never more — and parse the "Did you mean X?"
              suggestions servers leak in validation errors (GraphQL's suggestion
              algorithm only proposes real schema names, so a leaked suggestion is a
              real field even with introspection off). A bare-word probe that returns
              data, or an error implying the field exists (needs args / needs a
              selection), is recorded as an existence signal. This is a cheap first
              pass, NOT a full schema reconstruction — for a target that warrants
              deeper effort run the real `clairvoyance` tool (pip-installable) instead
              of scaling this up.
           -> NORMALIZED RESULT (same JSON contract as cms_detect.py)

Severity discipline (identical model to cms_detect.py's "detection is info"): finding
a GraphQL endpoint and dumping its schema is recon, not a vulnerability — both are
"info". Only two things earn their own "low" finding: (1) a field whose NAME matches
the sensitive-data pattern (password|secret|token|key|ssn|creditcard|email|admin|
internal|debug|role|permission — case-insensitive substring) — an info-disclosure
LEAD whose next_action says to test with two accounts per graphql.md's IDOR method;
this alone is not a finding. (2) The aliased-introspection bypass succeeding after a
plain block — an actual WAF/middleware rule gap, distinct from the schema content it
recovers. Field-suggestion leaks are "info" (weak signal). Never auto-escalate.

Scope notes: introspection may be OFF over HTTP but ON over WebSocket
(graphql-transport-ws) — out of scope here (websocket.md §5 territory); whenever
introspection ends up fully blocked the result's next_action says to retry there.
All requests are read-only POSTs of benign GraphQL documents — no login attempts, no
payload injection; the fallback wordlist is bounded and generic (no real company's
schema is encoded). Same scope discipline as every script in this repo: run against
in-scope targets only.

Zero pip dependencies by design — `pip install` routinely fails under PEP-668 on
sandboxed engagement boxes (house precedent: cms_detect.py, subdomain_takeover.py).
Pure stdlib HTTP probing; the HTTP client is adapted from cms_detect.probe_http
(64KB body cap, TLS verify off for intercepting proxies, capped hop-logged
redirects). No external binary, no find_tool() seam (deliberately: nothing here
shells out). Python 3.8+ (future-annotations for the 3.8 interpreter).

Usage:
    python3 graphql_recon.py https://target.example [more ...]   # base URL; paths probed for you
    python3 graphql_recon.py -l recon/live.txt --json --output gql.json
    python3 graphql_recon.py https://target.example --all-paths  # enumerate EVERY endpoint
    python3 graphql_recon.py target.example --verbose            # stage-by-stage to stderr

Exit code: 0 for a completed scan — including "no GraphQL endpoint found" (a valid
negative result, not an error). Non-zero (2) only for hard errors: no targets,
missing/unreadable -l file, --timeout <= 0, --threads < 1.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TOOL = "graphql_recon"
SOURCE = "graphql_recon.py"

MAX_BODY_BYTES = 64 * 1024   # GraphQL responses we care about are small; never buffer a whole site
MAX_REDIRECTS = 4            # hop-logged, then give up (cms_detect.probe_http precedent)
DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 10         # OUTER loop: targets scanned concurrently
USER_AGENT = "Mozilla/5.0 (compatible; moraa-graphqlrecon/1.0; authorized-scope-use-only)"

# graphql.md "Discover & map" — the exact path list, in the doc's order.
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/console",
                 "/graphiql", "/playground", "/query", "/gql"]

# Minimal well-formed query every GraphQL schema answers; its response shape
# (top-level "data"/"errors" JSON) is the endpoint-confirmation oracle.
DISCOVERY_QUERY = "{__typename}"

# graphql.md's exact introspection query, plus queryType/mutationType/
# subscriptionType{name} — the three extra meta-fields are always legal
# introspection parts and let root fields be attributed deterministically
# (some engines name roots query_root/mutation_root, not Query/Mutation).
INTROSPECTION_QUERY = ("query{__schema{queryType{name} mutationType{name} "
                       "subscriptionType{name} "
                       "types{name fields{name args{name} type{name}}}}}")

# graphql.md's aliased-introspection bypass: the WAF sees `my_alias:` where its
# rule expects the bare `__schema {` pattern, the server still resolves it.
# Full field shape under the alias, so a success recovers the whole schema in
# ONE request.
ALIAS_NAME = "my_alias"
ALIASED_INTROSPECTION_QUERY = ("query { my_alias: __schema {queryType{name} "
                               "mutationType{name} subscriptionType{name} "
                               "types{name fields{name args{name} type{name}}}} }")

# Task-mandated core (graphql_recon TASK-015 wordlist floor).
WORDLIST_CORE = [
    "id", "user", "users", "me", "viewer", "node", "account", "accounts", "admin",
    "config", "settings", "search", "query", "list", "get", "create", "update",
    "delete", "login", "logout", "auth", "token", "session", "profile", "order",
    "orders", "product", "products", "payment", "transaction", "balance", "transfer",
    "health", "status", "version", "__type",
]
# Generic entity nouns — the plural/singular pairs matter: suggestion engines
# propose near-neighbours, so probing one form surfaces the other.
WORDLIST_ENTITIES = [
    "nodes", "items", "item", "posts", "post", "comments", "comment", "messages",
    "message", "notifications", "notification", "files", "file", "images", "image",
    "uploads", "upload", "teams", "team", "organizations", "organization", "orgs",
    "projects", "project", "tasks", "task", "events", "event", "invoices", "invoice",
    "subscriptions", "subscription", "payments", "cards", "card", "wallets", "wallet",
    "refunds", "payouts", "documents", "document", "reports", "analytics",
    "auditLogs", "apiKeys", "apiKey", "keys", "secrets", "devices", "device",
    "addresses", "sessions", "roles", "permissions", "groups", "categories", "tags",
    "reviews", "carts", "cart", "checkout", "inventory", "shipments", "coupons",
    "campaigns", "customers", "employees", "company", "tenant", "tenants",
    "workspaces", "workspace", "transactions", "transactionsConnection",
]
# CRUD stems + infra/meta names: probing a bare stem ("get") triggers suggestions
# for every matching real field ("getUser", "getAllUsers", ...) — the cheapest
# signal-per-request trick in the error-suggestion oracle.
WORDLIST_STEMS_INFRA = [
    "all", "find", "fetch", "currentUser", "allUsers", "getUser", "email", "phone",
    "metrics", "logs", "debug", "featureFlags", "environment", "ping", "info",
    "whoami", "countries", "currencies", "languages", "time", "limits",
]
FIELD_WORDLIST = WORDLIST_CORE + WORDLIST_ENTITIES + WORDLIST_STEMS_INFRA

# Task-specified sensitive-name pattern (case-insensitive substring), + credit_card
# as a documented snake_case variant of creditcard.
SENSITIVE_RE = re.compile(r"password|secret|token|key|ssn|creditcard|credit_card|"
                          r"email|admin|internal|debug|role|permission", re.IGNORECASE)
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ROOT_NAME_HEURISTICS = {"query", "mutation", "subscription",
                         "query_root", "mutation_root", "subscription_root"}

MAX_SENSITIVE_FINDINGS = 10   # individual low findings per target; overflow stays in metadata
MAX_SENSITIVE_META = 25
MAX_SUGGESTION_EVIDENCE = 20
MAX_ROOT_FIELD_EVIDENCE = 30
MAX_TYPE_NAME_EVIDENCE = 60
MAX_ERRORS = 15


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _excerpt(body: str | None, limit: int = 160) -> str:
    if not body:
        return ""
    flat = " ".join(body.split())
    return flat[:limit] + ("..." if len(flat) > limit else "")


# --------------------------------------------------------------------------
# HTTP probe (stdlib urllib — adapted from cms_detect.probe_http verbatim: bounded
# 64KB body, TLS verify off for intercepting proxies, capped hop-logged redirects;
# POST when `data` is given, which is every request this script makes)
# --------------------------------------------------------------------------

def _build_opener() -> urllib.request.OpenerDirector:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # engagement boxes run intercepting proxies (sibling precedent)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # we follow redirects ourselves, hop by hop, and log each one

    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))


_OPENER = _build_opener()


def _headers_to_dict(hdrs) -> dict:
    out: dict = {}
    for k, v in hdrs.items():
        out[k.lower()] = v
    sc = hdrs.get_all("Set-Cookie") if hasattr(hdrs, "get_all") else None
    if sc:
        out["set-cookie"] = "; ".join(sc)
    return out


def probe_http(url: str, timeout: float, data: bytes | None = None) -> dict:
    """One bounded GET (or POST when `data` given). Redirects followed up to MAX_REDIRECTS
    (each hop logged). Returns {url, final_url, status, headers, body, error, redirects};
    4xx/5xx/3xx are responses (error=None) — only transport failures set error."""
    method = "POST" if data is not None else "GET"
    extra = {"Content-Type": "application/json"} if data is not None else {}
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*",
               "Accept-Encoding": "identity", "Connection": "close", **extra}
    hops: list[dict] = []
    cur = url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            req = urllib.request.Request(cur, data=data, headers=headers, method=method)
            try:
                with _OPENER.open(req, timeout=timeout) as resp:
                    return {"url": url, "final_url": resp.geturl(), "status": resp.status,
                            "headers": _headers_to_dict(resp.headers),
                            "body": resp.read(MAX_BODY_BYTES).decode("utf-8", "replace"),
                            "error": None, "redirects": hops}
            except urllib.error.HTTPError as e:  # 3xx (no-redirect opener), 4xx, 5xx
                loc = e.headers.get("Location")
                if 300 <= e.code < 400 and loc and len(hops) < MAX_REDIRECTS:
                    hops.append({"status": e.code, "location": loc})
                    cur = urllib.parse.urljoin(cur, loc)
                    continue
                try:
                    body = e.read(MAX_BODY_BYTES).decode("utf-8", "replace")
                except Exception:
                    body = ""
                return {"url": url, "final_url": cur, "status": e.code,
                        "headers": _headers_to_dict(e.headers), "body": body,
                        "error": None, "redirects": hops}
        return {"url": url, "final_url": cur, "status": None, "headers": {}, "body": None,
                "error": f"too many redirects (> {MAX_REDIRECTS})", "redirects": hops}
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as e:
        return {"url": url, "final_url": cur, "status": None, "headers": {}, "body": None,
                "error": f"{type(e).__name__}: {e}", "redirects": hops}


# --------------------------------------------------------------------------
# GraphQL response parsing (pure functions — unit-tested directly)
# --------------------------------------------------------------------------

def is_graphql_shape(js) -> bool:
    """GraphQL's own response envelope: a JSON object with a top-level "data" or
    "errors" key. A generic 404/HTML page — or a REST-style {"message": "..."} —
    is NOT a hit even when it returns HTTP 200."""
    return isinstance(js, dict) and ("data" in js or "errors" in js)


def extract_schema(js) -> dict | None:
    """The __schema payload from an introspection response — under the literal key,
    or under the alias key when the aliased-bypass form was sent."""
    if not isinstance(js, dict):
        return None
    data = js.get("data")
    if not isinstance(data, dict):
        return None
    for key in ("__schema", ALIAS_NAME):
        v = data.get(key)
        if isinstance(v, dict):
            return v
    return None


def first_error_message(js) -> str | None:
    if isinstance(js, dict):
        errs = js.get("errors")
        if isinstance(errs, list) and errs:
            first = errs[0]
            if isinstance(first, dict) and isinstance(first.get("message"), str):
                return first["message"]
            return str(first)
    return None


def parse_did_you_mean(message: str) -> list[str]:
    """Quoted suggestions from a GraphQL validation error — 'Cannot query field "usr"
    on type "Query". Did you mean "user" or "users"?'. GraphQL's suggestion algorithm
    only proposes names that exist in the schema, so each returned string is a real
    schema name even when introspection is off. Non-identifier suggestions (the
    'users { ... }' expansion form, enum values with odd characters) are dropped."""
    idx = message.lower().find("did you mean")
    if idx < 0:
        return []
    tail = message[idx + len("did you mean"):].strip().rstrip("?.! ")
    out, seen = [], set()
    for s in re.findall(r'"([^"]*)"', tail):
        if _IDENT_RE.fullmatch(s) and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _type_label(t) -> str:
    """Best-effort display of a type reference. graphql.md's query asks only for
    type{name}, which is null for NON_NULL/LIST wrappers — render those as [inner]
    when ofType happens to be present, else '?' (never a fabricated name)."""
    if isinstance(t, dict):
        name = t.get("name")
        if name:
            return str(name)
        inner = _type_label(t.get("ofType")) if t.get("ofType") else None
        return f"[{inner}]" if inner else "?"
    if isinstance(t, str):
        return t
    return "?"


def render_field(field: dict) -> str:
    """One field -> 'name(arg: Type, ...) -> RetType' for evidence lines."""
    name = field.get("name", "?")
    args = [a for a in (field.get("args") or []) if isinstance(a, dict)]
    rendered_args = ", ".join(f"{a.get('name', '?')}: {_type_label(a.get('type'))}" for a in args)
    return f"{name}({rendered_args}) -> {_type_label(field.get('type'))}"


def summarize_schema(schema: dict) -> dict:
    """Type names, root operations (via queryType/mutationType/subscriptionType, with
    a name-heuristic fallback for engines that omit them), and sensitive-name field
    matches across ALL types (root resolvers are where authz bugs pay, but a
    'passwordHash' on User is the same lead)."""
    types = [t for t in (schema.get("types") or []) if isinstance(t, dict) and t.get("name")]

    def fields_of(t: dict) -> list[dict]:
        return [f for f in (t.get("fields") or []) if isinstance(f, dict) and f.get("name")]

    root_names = []
    for key in ("queryType", "mutationType", "subscriptionType"):
        rt = schema.get(key)
        if isinstance(rt, dict) and rt.get("name") and rt["name"] not in root_names:
            root_names.append(rt["name"])
    if not root_names:  # heuristic fallback when the pointers are absent
        root_names = [t["name"] for t in types
                      if str(t["name"]).lower() in _ROOT_NAME_HEURISTICS]

    root_fields: list[str] = []
    for rn in root_names:
        for t in types:
            if t["name"] == rn:
                root_fields.extend(render_field(f) for f in fields_of(t))

    sensitive: list[str] = []
    seen = set()
    for t in types:
        for f in fields_of(t):
            if SENSITIVE_RE.search(f["name"]):
                entry = f"{t['name']}.{f['name']}"
                if entry not in seen:
                    seen.add(entry)
                    sensitive.append(entry)

    return {
        "type_count": len(types),
        "type_names": [t["name"] for t in types],
        "root_types": root_names,
        "root_fields": root_fields,
        "root_field_count": len(root_fields),
        "sensitive_fields": sensitive,
    }


# --------------------------------------------------------------------------
# the pipeline
# --------------------------------------------------------------------------

def normalize_target(target: str) -> list[str]:
    """Bare host -> [https://host, http://host] fallback candidates. A full URL is used
    as-is (path preserved). Trailing slashes stripped."""
    t = target.strip().rstrip("/")
    if "://" in t:
        return [t]
    return ["https://" + t, "http://" + t]


def path_candidates(target: str) -> tuple[list[str], str]:
    """Paths to probe under a base: the caller's own path verbatim first (they may
    already know the endpoint — https://T/graphql re-probes exactly that), then
    graphql.md's list. Returns (paths, own_path)."""
    parts = urllib.parse.urlsplit(target if "://" in target else "https://" + target)
    own = parts.path or ""
    out: list[str] = []
    if own and own != "/":
        out.append(own)
    for p in GRAPHQL_PATHS:
        if p != own:
            out.append(p)
    return out, own


def introspect_endpoint(url: str, post, ev) -> dict:
    """Stage 2 on one confirmed endpoint. Returns {status, schema, bypass, notes} where
    status is one of: enabled / blocked-retried-aliased-succeeded / disabled /
    auth-required. The disabled-vs-auth distinction is the {__typename} re-probe: a
    live endpoint that answers the trivial query but refuses __schema has
    introspection disabled; an endpoint that refuses BOTH requires auth and no
    fallback stage runs (suggestion mining would only produce auth errors)."""
    probe, js = post(url, INTROSPECTION_QUERY)
    schema = extract_schema(js)
    if schema is not None:
        ev(f"introspection: full __schema query succeeded at {url}")
        return {"status": "enabled", "schema": schema, "bypass": False}
    plain_note = first_error_message(js) or (
        f"HTTP {probe['status']} non-JSON/empty body" if probe["error"] is None
        else probe["error"])
    ev(f"introspection: plain __schema query failed — {_excerpt(plain_note, 160)}")

    _, js2 = post(url, DISCOVERY_QUERY)
    alive = isinstance(js2, dict) and isinstance(js2.get("data"), dict)
    if not alive:
        note = first_error_message(js2) or "no data in response"
        ev(f"introspection: {DISCOVERY_QUERY} also fails ({_excerpt(note, 120)}) — "
           f"endpoint requires auth; introspection availability unknown, "
           f"field-suggestion fallback skipped")
        return {"status": "auth-required", "schema": None, "bypass": False}

    ev("introspection: {__typename} still answers — endpoint is live, so the block "
       "targets the __schema keyword (introspection disabled/blocked), not the endpoint")
    probe3, js3 = post(url, ALIASED_INTROSPECTION_QUERY)
    schema3 = extract_schema(js3)
    if schema3 is not None:
        ev(f"introspection: aliased bypass SUCCEEDED at {url} — "
           f"`{ALIAS_NAME}: __schema` dodged the block (graphql.md technique)")
        return {"status": "blocked-retried-aliased-succeeded", "schema": schema3, "bypass": True}
    note3 = first_error_message(js3) or "no schema in response"
    ev(f"introspection: aliased bypass also failed ({_excerpt(note3, 120)}) — "
       f"introspection disabled, falling back to field suggestions")
    return {"status": "disabled", "schema": None, "bypass": False}


def field_suggestion_fallback(url: str, post, ev) -> dict:
    """Stage 3 — Clairvoyance-style, BOUNDED: exactly one request per wordlist entry
    (~140 total). Parses "Did you mean" suggestions out of validation errors and
    records existence signals (bare query returned data / error implies the field
    exists). NOT full schema reconstruction — the next_action of any finding built
    from this says to run the real `clairvoyance` tool for that."""
    suggestions: dict[str, str] = {}   # suggested name -> probe word that surfaced it
    exists: list[str] = []
    seen_exists = set()
    probes_sent = 0
    transport_failures = 0
    for word in FIELD_WORDLIST:
        probe, js = post(url, "{" + word + "}")
        probes_sent += 1
        if probe["error"] is not None:
            transport_failures += 1
            continue
        msgs: list[str] = []
        if isinstance(js, dict):
            for e in js.get("errors") or []:
                m = e.get("message") if isinstance(e, dict) else None
                if isinstance(m, str):
                    msgs.append(m)
        data = js.get("data") if isinstance(js, dict) else None
        if isinstance(data, dict) and word in data and not msgs:
            if word not in seen_exists:
                seen_exists.add(word)
                exists.append(f'"{word}" — bare query returned data (field exists)')
            continue
        for m in msgs:
            low = m.lower()
            if "must have a selection of subfields" in low and word in low:
                if word not in seen_exists:
                    seen_exists.add(word)
                    exists.append(f'"{word}" — server error implies the field exists '
                                  f'(object type): {_excerpt(m, 120)}')
            elif "did you mean" in low:
                for s in parse_did_you_mean(m):
                    if s != word:
                        suggestions.setdefault(s, word)
            elif word in m and "cannot query field" not in low:
                if word not in seen_exists:
                    seen_exists.add(word)
                    exists.append(f'"{word}" — server error implies the field exists: '
                                  f'{_excerpt(m, 120)}')
    ev(f"field-suggestion fallback: {probes_sent} wordlist probe(s) sent, "
       f"{len(suggestions)} suggestion(s) and {len(exists)} existence signal(s) captured"
       + (f" ({transport_failures} transport failure(s))" if transport_failures else ""))
    return {"probes_sent": probes_sent, "suggestions": suggestions,
            "exists": exists, "transport_failures": transport_failures}


def scan_target(target: str, timeout: float = DEFAULT_TIMEOUT, all_paths: bool = False,
                verbose: bool = False) -> dict:
    """Full pipeline for one target; returns the normalized result object."""
    evidence: list[str] = []
    errors: list[str] = []
    requests_made = 0

    def ev(msg: str) -> None:
        evidence.append(msg)
        if verbose:
            eprint(f"  [{target}] {msg}")

    def post(url: str, query: str):
        nonlocal requests_made
        requests_made += 1
        body = json.dumps({"query": query}).encode("utf-8")
        probe = probe_http(url, timeout, data=body)
        js = None
        if probe["error"] is None and probe.get("body"):
            try:
                js = json.loads(probe["body"])
            except ValueError:
                js = None
        return probe, js

    # ---- stage 1: endpoint discovery ----------------------------------------
    candidates, own_path = path_candidates(target)
    hits: list[str] = []
    path_probes: list[dict] = []
    for base in normalize_target(target):
        got_response = False
        for path in candidates:
            url = base if path == own_path else base + path
            probe, js = post(url, DISCOVERY_QUERY)
            hit = probe["error"] is None and is_graphql_shape(js)
            path_probes.append({"path": path, "url": url,
                                "status": probe["status"], "hit": hit})
            if probe["error"] is not None:
                errors.append(f"POST {url}: {probe['error']}")
                continue
            got_response = True
            if hit:
                final = probe.get("final_url") or url
                hits.append(final)
                typename = None
                if isinstance(js, dict) and isinstance(js.get("data"), dict):
                    typename = js["data"].get("__typename")
                ev(f"discovery: POST {url} -> HTTP {probe['status']} GraphQL-shaped "
                   f"response" + (f" (__typename={typename})" if typename else "")
                   + f" — endpoint confirmed: {final}")
            else:
                ev(f"discovery: POST {url} -> HTTP {probe['status']}, not "
                   f"GraphQL-shaped — skipped")
            if hit and not all_paths:
                break
        if got_response:
            break  # this scheme answers — never blind-sweep the http fallback too

    # ---- no endpoint: clean negative result (valid outcome, exit 0) ----------
    if not hits:
        ev(f"discovery: no GraphQL endpoint found on {len(path_probes)} probed path(s)")
        return {
            "tool": TOOL, "target": target, "timestamp": now_iso(), "status": "success",
            "findings": [], "evidence": list(evidence),
            "errors": _collapse_errors(errors),
            "metadata": {
                "endpoint_found": None, "additional_endpoints": [],
                "introspection_status": "not-applicable-no-endpoint",
                "type_count": None, "root_field_count": None, "root_types": None,
                "sensitive_fields_flagged": [], "path_probes": path_probes,
                "fallback": {"ran": False, "probes_sent": 0, "suggestions": [],
                             "exists_signals": []},
                "requests_made": requests_made, "timeout_s": timeout,
                "wordlist_size": len(FIELD_WORDLIST),
            },
        }

    # ---- stages 2+3 per confirmed endpoint -----------------------------------
    findings: list[dict] = []
    per_endpoint: list[dict] = []
    sensitive_union: list[str] = []
    fallback_note = None
    primary_summary = None
    for idx, endpoint in enumerate(hits):
        info = introspect_endpoint(endpoint, post, ev)
        summary = summarize_schema(info["schema"]) if info["schema"] else None
        if summary:
            # the schema summary belongs in the result-level evidence log too —
            # it is what --verbose surfaces for the human running this
            ev(f"schema: {summary['type_count']} type(s), {summary['root_field_count']} "
               f"root field(s) across {', '.join(summary['root_types']) or 'unknown roots'}")
            for line in summary["root_fields"][:MAX_ROOT_FIELD_EVIDENCE]:
                ev(f"schema root: {line}")
        if idx == 0:
            primary_summary = summary
        per_endpoint.append({
            "endpoint": endpoint, "introspection_status": info["status"],
            "type_count": summary["type_count"] if summary else None,
            "root_field_count": summary["root_field_count"] if summary else None,
        })
        findings.extend(_endpoint_findings(target, endpoint, info, summary))
        if summary:
            for s in summary["sensitive_fields"]:
                if s not in sensitive_union:
                    sensitive_union.append(s)
        # stage 3 runs ONCE per target, on the primary endpoint, only when
        # introspection is genuinely disabled (never on auth-required — the
        # suggestions would be auth errors, i.e. garbage)
        if idx == 0 and info["status"] == "disabled":
            fb = field_suggestion_fallback(endpoint, post, ev)
            fallback_note = fb
            leak = _suggestion_finding(target, endpoint, fb)
            if leak:
                findings.append(leak)

    primary = per_endpoint[0]
    return {
        "tool": TOOL, "target": target, "timestamp": now_iso(), "status": "success",
        "findings": findings, "evidence": list(evidence),
        "errors": _collapse_errors(errors),
        "metadata": {
            "endpoint_found": hits[0],
            "additional_endpoints": hits[1:],
            "introspection_status": primary["introspection_status"],
            "type_count": primary["type_count"],
            "root_field_count": primary["root_field_count"],
            "root_types": primary_summary["root_types"] if primary_summary else None,
            "sensitive_fields_flagged": sensitive_union[:MAX_SENSITIVE_META],
            "path_probes": path_probes,
            "fallback": {
                "ran": fallback_note is not None,
                "probes_sent": fallback_note["probes_sent"] if fallback_note else 0,
                "suggestions": (sorted(fallback_note["suggestions"])[:MAX_SENSITIVE_META]
                                if fallback_note else []),
                "exists_signals": (fallback_note["exists"][:MAX_SUGGESTION_EVIDENCE]
                                   if fallback_note else []),
            },
            "per_endpoint": per_endpoint,
            "requests_made": requests_made,
            "timeout_s": timeout,
            "wordlist_size": len(FIELD_WORDLIST),
        },
    }


def _collapse_errors(errors: list[str]) -> list[str]:
    """Unique preserve-order, capped — a dead target produces one near-identical
    transport error per probed path and that noise is not worth 15 lines."""
    out: list[str] = []
    seen = set()
    for e in errors:
        if e not in seen:
            seen.add(e)
            out.append(e)
    if len(out) > MAX_ERRORS:
        dropped = len(out) - MAX_ERRORS
        out = out[:MAX_ERRORS] + [f"... ({dropped} more probe failure(s) suppressed)"]
    return out


def _endpoint_findings(target: str, endpoint: str, info: dict, summary: dict | None) -> list[dict]:
    """Findings for one confirmed endpoint: discovery (info) always; schema dump
    (info) + bypass (low) + sensitive-name leads (low, capped) as earned."""
    out: list[dict] = []
    status = info["status"]

    endpoint_action = ("Map operations from the schema and test object/field-level "
                       "authz with two accounts per graphql.md's Method — endpoint "
                       "discovery alone is recon, not a finding.")
    if status == "disabled":
        endpoint_action += (" Introspection is blocked over HTTP: run the real "
                            "`clairvoyance` tool for exhaustive schema reconstruction, "
                            "and retry introspection over WebSocket "
                            "(graphql-transport-ws) where it may still be enabled — "
                            "see websocket.md §5.")
    elif status == "auth-required":
        endpoint_action += (" The endpoint answered discovery-shaped JSON but requires "
                            "authentication for real queries — re-run this probe with "
                            "an authenticated session before concluding anything about "
                            "introspection.")
    out.append({
        "type": "graphql_endpoint_discovered", "severity": "info", "confidence": 0.9,
        "target": target, "endpoint": endpoint,
        "evidence": [f"POST {endpoint} with {{\"query\": \"{DISCOVERY_QUERY}\"}} returned "
                     f"GraphQL-shaped JSON (top-level data/errors)"],
        "source": SOURCE, "next_action": endpoint_action,
    })

    if summary is None:
        return out

    field_lines = summary["root_fields"][:MAX_ROOT_FIELD_EVIDENCE]
    if len(summary["root_fields"]) > MAX_ROOT_FIELD_EVIDENCE:
        field_lines.append(f"... +{len(summary['root_fields']) - MAX_ROOT_FIELD_EVIDENCE} "
                           f"more root fields")
    type_names = summary["type_names"][:MAX_TYPE_NAME_EVIDENCE]
    type_note = (f"{summary['type_count']} types"
                 + (f" (first {MAX_TYPE_NAME_EVIDENCE}: {', '.join(type_names)})"
                    if summary["type_count"] > MAX_TYPE_NAME_EVIDENCE else
                    (f": {', '.join(type_names)}" if type_names else "")))
    out.append({
        "type": "graphql_schema_exposed", "severity": "info", "confidence": 0.95,
        "target": target, "endpoint": endpoint,
        "evidence": ([f"introspection succeeded at {endpoint} (status: {status}) — "
                      f"{type_note}",
                      f"{summary['root_field_count']} root field(s) across "
                      f"{len(summary['root_types'])} root type(s) "
                      f"({', '.join(summary['root_types']) or 'unknown'})"]
                     + [f"root: {line}" for line in field_lines]),
        "source": SOURCE,
        "next_action": ("Enumerate every root operation and test the sensitive ones with "
                        "two accounts (object/field-level IDOR) and mutation "
                        "mass-assignment per graphql.md's Method — a schema dump is "
                        "recon/info, not by itself a vulnerability."),
    })

    if info["bypass"]:
        out.append({
            "type": "graphql_introspection_bypass", "severity": "low", "confidence": 0.9,
            "target": target, "endpoint": endpoint,
            "evidence": ["plain introspection query was blocked, but the aliased form "
                         f"`query {{ {ALIAS_NAME}: __schema {{...}} }}` (graphql.md's "
                         "documented technique) returned a full schema — a WAF/"
                         "middleware rule matches the bare __schema keyword pattern "
                         "only",
                         f"recovered schema: {summary['type_count']} types, "
                         f"{summary['root_field_count']} root fields"],
            "source": SOURCE,
            "next_action": ("Report the WAF/middleware rule gap with the exact bypassing "
                            "query (graphql.md §aliased-introspection-bypass); check "
                            "whether the same rule also guards mutations — the recovered "
                            "schema content is reported separately as schema_exposed."),
        })

    for entry in summary["sensitive_fields"][:MAX_SENSITIVE_FINDINGS]:
        out.append({
            "type": "graphql_sensitive_field_flagged", "severity": "low",
            "confidence": 0.75, "target": target, "endpoint": endpoint, "field": entry,
            "evidence": [f"field '{entry}' matches the sensitive-name pattern "
                         f"(password|secret|token|key|ssn|creditcard|email|admin|"
                         f"internal|debug|role|permission, case-insensitive substring) "
                         f"and is reachable via introspection at {endpoint}"],
            "source": SOURCE,
            "next_action": ("Test with two accounts per graphql.md's IDOR method — this "
                            "alone is not a finding: a name match is an info-disclosure "
                            "lead, not a vulnerability."),
        })
    return out


def _suggestion_finding(target: str, endpoint: str, fb: dict) -> dict | None:
    """Info finding when the bounded fallback surfaced signal (suggestions and/or
    existence signals). Explicitly points at the real clairvoyance tool — this stage
    is a cheap first pass, not a reconstruction."""
    suggestions = sorted(fb["suggestions"])
    if not suggestions and not fb["exists"]:
        return None
    evidence = [f"introspection disabled at {endpoint}; bounded field-suggestion pass "
                f"({fb['probes_sent']} wordlist probe(s), one per word) leaked:"]
    shown = suggestions[:MAX_SUGGESTION_EVIDENCE]
    for s in shown:
        evidence.append(f'suggestion: probing "{fb["suggestions"][s]}" -> server '
                        f'suggested "{s}" (real schema name — suggestion engines only '
                        f'propose existing fields)')
    evidence.extend(fb["exists"][:MAX_SUGGESTION_EVIDENCE])
    if len(suggestions) > MAX_SUGGESTION_EVIDENCE:
        evidence.append(f"... +{len(suggestions) - MAX_SUGGESTION_EVIDENCE} more "
                        f"suggestion(s)")
    return {
        "type": "graphql_field_suggestion_leak", "severity": "info", "confidence": 0.7,
        "target": target, "endpoint": endpoint, "evidence": evidence, "source": SOURCE,
        "next_action": ("Run the real `clairvoyance` tool (pip-installable: "
                        "`pip install clairvoyance`; `clairvoyance -o schema.json "
                        f"{endpoint}`) for exhaustive schema reconstruction on this "
                        "endpoint — this pass is bounded signal, not reconstruction. "
                        "Introspection may also still be enabled over WebSocket "
                        "(graphql-transport-ws) — see websocket.md §5."),
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def load_target_list(path: str) -> list[str]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"list file not found: {path}")
    out: list[str] = []
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln)
    return out


def print_human(results: list[dict], quiet: bool) -> None:
    if quiet:
        return
    for r in results:
        md = r.get("metadata", {})
        ep = md.get("endpoint_found")
        if ep:
            line = f"GraphQL endpoint {ep} — introspection: {md.get('introspection_status')}"
            if md.get("type_count") is not None:
                line += f" — {md['type_count']} type(s), {md['root_field_count']} root field(s)"
            if md.get("sensitive_fields_flagged"):
                line += (f" — {len(md['sensitive_fields_flagged'])} sensitive-name "
                         f"field(s) flagged")
            if md.get("additional_endpoints"):
                line += f" — +{len(md['additional_endpoints'])} more endpoint(s) (--all-paths)"
            eprint(f"[{r['target']}] {line}")
        else:
            n = len(md.get("path_probes") or [])
            eprint(f"[{r['target']}] no GraphQL endpoint found ({n} path probe(s))")
        for err in r.get("errors", []):
            eprint(f"[{r['target']}] ERROR: {err}")
        lows = [f for f in r.get("findings", []) if f.get("severity") == "low"]
        for f in lows:
            detail = f.get("field") or f.get("type")
            eprint(f"[{r['target']}] LOW: {f['type']}: {detail}")
            eprint(f"  -> {f['next_action']}")
    eprint("")
    eprint("Next: route confirmed endpoints through graphql.md's Method — two-account "
           "object/field-level authz tests on every sensitive root operation; "
           "introspection blocked -> clairvoyance + websocket.md §5 retry; endpoint "
           "discovery is recon, not a finding")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=SOURCE,
        description="GraphQL recon (graphql.md automated): endpoint discovery, "
                    "introspection dump with aliased-bypass retry, bounded "
                    "field-suggestion fallback. Recon/mapping only — endpoint "
                    "discovery and schema dumps are info; exploitation (IDOR, "
                    "mass-assignment, batching) stays manual per graphql.md.",
        epilog="examples:\n"
               "  %(prog)s https://target.example\n"
               "  %(prog)s -l recon/live.txt --json --output graphql.json\n"
               "  %(prog)s https://target.example --all-paths --verbose\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", metavar="target",
                    help="target base URL(s) or bare host(s) (the path list is probed "
                         "for you; bare hosts try https then http)")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file of targets, one per line (# comments allowed)")
    ap.add_argument("--all-paths", action="store_true",
                    help="enumerate EVERY confirmed GraphQL endpoint instead of "
                         "stopping at the first (some apps expose several)")
    ap.add_argument("--json", action="store_true",
                    help="machine output on stdout (normalized JSON; array when >1 target)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SEC",
                    help="per-HTTP-operation timeout in seconds (default: 5)")
    ap.add_argument("--threads", type=int, default=DEFAULT_THREADS, metavar="N",
                    help="concurrent workers for multiple targets (default: 10)")
    ap.add_argument("--output", metavar="FILE",
                    help="also write the JSON result(s) to this file")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress the human-readable summary (no effect with --json)")
    ap.add_argument("--verbose", action="store_true",
                    help="print each pipeline stage's evidence to stderr as it runs")
    args = ap.parse_args(argv)

    targets: list[str] = list(args.targets)
    if args.list:
        try:
            targets.extend(load_target_list(args.list))
        except (OSError, FileNotFoundError) as e:
            eprint(f"[!] {e}")
            return 2
    if not targets:
        ap.error("no targets given (positional args or -l/--list FILE)")
    if args.timeout <= 0:
        ap.error("--timeout must be > 0")
    if args.threads < 1:
        ap.error("--threads must be >= 1")

    # dedupe, preserve order
    seen: set = set()
    targets = [t for t in targets if not (t.lower() in seen or seen.add(t.lower()))]

    if not args.quiet and not args.json:
        eprint(f"[*] {TOOL}: {len(targets)} target(s) | {len(GRAPHQL_PATHS)} paths + "
               f"caller path | fallback wordlist: {len(FIELD_WORDLIST)} | "
               f"timeout: {args.timeout}s | pure stdlib HTTP")

    def run_one(t: str) -> dict:
        try:
            return scan_target(t, timeout=args.timeout, all_paths=args.all_paths,
                               verbose=args.verbose)
        except Exception as e:  # never let one target kill the run
            return {"tool": TOOL, "target": t, "timestamp": now_iso(), "status": "success",
                    "findings": [], "evidence": [],
                    "errors": [f"unexpected error: {type(e).__name__}: {e}"],
                    "metadata": {"endpoint_found": None,
                                 "introspection_status": "not-applicable-no-endpoint",
                                 "timeout_s": args.timeout}}

    if len(targets) == 1:
        results = [run_one(targets[0])]
    else:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(args.threads, len(targets))) as ex:
            futures = {ex.submit(run_one, t): t for t in targets}
            by_target: dict = {}
            for fut in concurrent.futures.as_completed(futures):
                by_target[futures[fut]] = fut.result()
            results = [by_target[t] for t in targets]  # preserve input order

    payload: dict | list[dict] = results[0] if len(results) == 1 else results
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_human(results, quiet=args.quiet)

    if args.output:
        try:
            Path(args.output).write_text(json.dumps(payload, indent=2) + "\n",
                                         encoding="utf-8")
            if not args.quiet and not args.json:
                eprint(f"[*] JSON written to {args.output}")
        except OSError as e:
            eprint(f"[!] failed to write {args.output}: {e}")
            return 2

    return 0  # completed scan — exit non-zero only for hard errors above


if __name__ == "__main__":
    sys.exit(main())
