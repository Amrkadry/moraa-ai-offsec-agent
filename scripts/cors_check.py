#!/usr/bin/env python3
"""cors_check.py — credentialed-CORS misconfiguration checker (cors.md pipeline, zero pip deps).

WHY: cors.md is this repo's best-proven paid class (the enterprise-identity product same-site
wildcard *.acme.example -> AWS STS finding, and the remoteaccess.svc.acme.example per-route work) and it
is currently a hand-run curl one-liner repeated per bypass payload. This script automates the
doc's own pipeline, section by section, in three stages:

    BASELINE (one GET of the target with the replayed auth, no Origin — records status and
              the Set-Cookie SameSite attributes that decide real-world impact, §4)
      -> STAGE 1: BYPASS-PAYLOAD SWEEP (§1 one-request probe + the full §2 table): a battery
              of crafted Origin headers — pure reflection, suffix, prefix (raw + dashed),
              subdomain, underscore, Safari { } ` domain-split, scheme downgrade, userinfo
              confusion, null — each classified by §1's exact decision table
      -> STAGE 2: UNESCAPED-DOT SWEEP (§2b, ADAPTIVE — only when stage 1 shows a fixed
              allowlist and no attacker-origin reflection): mutate each dot of the legitimate
              origin's host to x/-/a/_ in turn; a reflecting mutant means the allowlist regex
              has an unescaped '.' at that position. NOT auto-escalated: whether the implied
              domain is registrable needs an RDAP/WHOIS check this script deliberately does
              not perform from inside a test run — it names the mutants and says what to verify.
      -> STAGE 3: SAMESITE DISCIPLINE (§4): parsed from the baseline response's Set-Cookie
              and folded into the verdict's evidence — a cross-site reflection under
              SameSite=Lax (or no attribute; modern browsers default to Lax) is DOWNgraded,
              while a same-site *.target.com match is the stronger lead.
    + PREFLIGHT (§2b): one OPTIONS with Access-Control-Request-Method for the best-scoring
              reflecting origin — some gateways reflect on the simple request but not on the
              preflight, which kills non-simple verbs. Consistency recorded in metadata.

THE ONE RULE (SKILL.md, verbatim discipline): "a credentialed-CORS finding is a precondition,
not an endpoint on its own, unless it independently reaches money/PII/creds AND the delivery
vector is already in hand." This script can only prove HEADER behavior — it cannot see the
response body's sensitivity or whether a delivery origin exists. Therefore the strongest
verdict it may ever emit is LIKELY, never CONFIRMED; every VULNERABLE-class finding's
next_action says exactly which human verification is still missing (real cross-origin data
read + delivery vector + SameSite, cors.md §3/§4/§5). Severity is capped at "medium" for
reflected-attacker-origin + ACAC:true for the same reason.

Attacker placeholder: every attacker-controlled origin uses "attacker-controlled.example"
(RFC 2606 reserved .example TLD — guaranteed never to resolve and owned by nobody). The
script only needs the TARGET to reflect the string; it never needs the origin to exist.
On a real engagement you would re-run the handful of hits with your actual registrable
domains (the cors.md "attackertarget.com" style); the reflection check is identical.

Severity/confidence discipline (never over-claim from one weak signal):
- reflected attacker origin + ACAC:true      -> "medium" (0.65, LIKELY) — precondition
- ACAO:null + ACAC:true                      -> "medium" (0.65, LIKELY) — sandboxed-iframe
                                                primitive needs no controlled domain (§3)
- unescaped-dot mutant reflecting + creds    -> "medium" (0.45, LIKELY) — registrability
                                                unverified; RDAP before treating as real (§2b)
- reflection WITHOUT ACAC:true               -> "low" (0.5) — browsers won't attach cookies;
                                                only escalates if the data is public-but-sensitive
- ACAO:* + ACAC:true                         -> "info" — browsers REJECT wildcard+credentials
                                                (Fetch spec); not exploitable, note-only
- ACAO:* alone                               -> "info" — public data only
- raw regex echoed back as ACAO              -> its own separate "low" info-disclosure finding
                                                (the allowlist regex leaked = hand-rolled CORS,
                                                cors.md §1 last row) — distinct from whether it
                                                is also exploitable
- no reflection anywhere, allowlist survives -> "info" NOT_VULNERABLE — recorded so coverage.md
                                                can tell "tested, clean" from "untested"
- one bad request/timeout                    -> that payload recorded as an error; the sweep
                                                never aborts (graceful degradation, house rule)

Scope discipline: read-only GET/OPTIONS probes with crafted Origin headers against targets
YOU are authorized to test. No login attempts, no brute force, no body tampering.

HTTP client: adapted from cms_detect.probe_http (bounded reads with the 64KB-class cap — CORS
fingerprint responses are tiny, NOT js_recon.py's bundle-sized cap — capped hop-logged
redirect-following, TLS verify off for intercepting proxies). Zero pip dependencies by design
(PEP-668 precedent: scripts/favicon_hash.py, scripts/subdomain_takeover.py, scripts/cms_detect.py).
Pure stdlib HTTP; no external binary. Python 3.8+ (annotations are strings via __future__).

Usage:
    python3 cors_check.py https://target.example/api/endpoint
    python3 cors_check.py https://target.example/api/account --cookie "SESSION=<value>"
    python3 cors_check.py https://target.example/api -H "Authorization: Bearer <token>"
    python3 cors_check.py -l recon/live.txt --json --output cors.json
    python3 cors_check.py https://target.example/api --verbose   # per-request evidence to stderr

Exit code: 0 for a completed scan (unreachable target or every request failing is still a
completed scan — failures land in errors[]), non-zero only for hard errors (bad args,
missing/unreadable -l file).
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

TOOL = "cors_check"
SOURCE = "cors_check.py"

USER_AGENT = "Mozilla/5.0 (compatible; moraa-corscheck/1.0; authorized-scope-use-only)"
MAX_BODY_BYTES = 64 * 1024   # CORS fingerprint responses are tiny — never buffer a whole site
MAX_REDIRECTS = 4            # hop-logged, then give up (cms_detect.probe_http precedent)

DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 10         # OUTER loop: targets scanned concurrently; the per-target
                             # payload sweep stays sequential so evidence is deterministic

# RFC 2606 reserved TLD — never resolvable, owned by nobody; see module docstring.
ATTACKER_PLACEHOLDER = "attacker-controlled.example"
SUBDOMAIN_PROBE_LABEL = "corscheck-probe"   # fixed label: deterministic, re-runnable evidence
MUTATION_CHARS = ("x", "-", "a", "_")       # cors.md §2b's exact set, in the doc's order

# Finding tiers per the module docstring's severity/confidence discipline.
CONF_VULN = 0.65             # reflected attacker origin + ACAC:true  (LIKELY, never CONFIRMED)
CONF_DOT = 0.45              # unescaped-dot mutant reflecting (registrability unverified)
CONF_NO_CREDS = 0.50
CONF_WILDCARD_CREDS = 0.85
CONF_WILDCARD = 0.80
CONF_CLEAN = 0.80
CONF_UNREACHABLE = 0.30
CONF_REGEX = 0.70

# ACAO values that look like a leaked hand-rolled regex (cors.md §1 last row: the raw regex
# string itself is echoed on a miss). A normal origin ("https://api.target.com") matches none.
REGEXISH_RE = re.compile(r"[\^$]|\.\*|\.\+|\[[^\]]*\]|\\\d|\(\?|\.\{")

# classification classes (cors.md §1 decision table rows + error)
CLASS_VULN = "reflected_with_credentials"            # VULNERABLE tier
CLASS_VULN_NULL = "null_reflected_with_credentials"  # VULNERABLE tier (sandboxed iframe, §3)
CLASS_NO_CREDS = "reflected_without_credentials"
CLASS_NULL_NO_CREDS = "null_reflected_without_credentials"
CLASS_WILDCARD_CREDS = "wildcard_with_credentials"   # spec-rejected — browser refuses
CLASS_WILDCARD = "wildcard_public"
CLASS_REGEX = "allowlist_regex_disclosed"
CLASS_ALLOWLIST = "allowlist_echoed"                 # a fixed (canonical) origin echoed on miss
CLASS_NO_ACAO = "no_acao"
CLASS_ERROR = "error"

REFLECTING_CLASSES = (CLASS_VULN, CLASS_VULN_NULL, CLASS_NO_CREDS, CLASS_NULL_NO_CREDS)

# preflight best-payload preference (first match wins)
PREFLIGHT_PRIORITY = (CLASS_VULN, CLASS_VULN_NULL, CLASS_NO_CREDS, CLASS_NULL_NO_CREDS)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# HTTP probe (single network seam — adapted from cms_detect.probe_http: bounded reads,
# capped hop-logged redirect-following, TLS verify off for intercepting proxies; plus
# explicit method + extra-header support because this script's whole job is Origin/OPTIONS
# variation, and Set-Cookie capture for the SameSite stage)
# --------------------------------------------------------------------------

def _build_opener() -> urllib.request.OpenerDirector:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # engagement boxes run intercepting proxies (sibling precedent)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # follow redirects ourselves, hop by hop, and log each one

    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))


_OPENER = _build_opener()


def _headers_to_dict(hdrs) -> tuple[dict, list]:
    """Lower-cased header dict (multiple Set-Cookie lines joined with '; ', cms_detect
    precedent) PLUS the raw Set-Cookie list kept separately for SameSite parsing."""
    out: dict = {}
    cookies: list = []
    if hdrs is None:
        return out, cookies
    for k, v in hdrs.items():
        out[k.lower()] = v
    if hasattr(hdrs, "get_all"):
        sc = hdrs.get_all("Set-Cookie")
        if sc:
            out["set-cookie"] = "; ".join(sc)
            cookies = list(sc)
    return out, cookies


def http_probe(url: str, timeout: float, method: str = "GET",
               extra_headers: dict | None = None) -> dict:
    """One bounded GET/OPTIONS (redirects followed up to MAX_REDIRECTS, each hop logged).
    Returns {url, final_url, status, headers, body, set_cookies, error, redirects};
    4xx/5xx/3xx are responses (error=None) — only transport failures set error."""
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*",
               "Accept-Encoding": "identity", "Connection": "close", **(extra_headers or {})}
    hops: list = []
    cur = url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            req = urllib.request.Request(cur, headers=headers, method=method)
            try:
                with _OPENER.open(req, timeout=timeout) as resp:
                    hdrs, cookies = _headers_to_dict(resp.headers)
                    return {"url": url, "final_url": resp.geturl(), "status": resp.status,
                            "headers": hdrs, "body": resp.read(MAX_BODY_BYTES).decode("utf-8", "replace"),
                            "set_cookies": cookies, "error": None, "redirects": hops}
            except urllib.error.HTTPError as e:  # 3xx (no-redirect opener), 4xx, 5xx
                loc = e.headers.get("Location") if e.headers else None
                if 300 <= e.code < 400 and loc and len(hops) < MAX_REDIRECTS:
                    hops.append({"status": e.code, "location": loc})
                    cur = urllib.parse.urljoin(cur, loc)
                    continue
                hdrs, cookies = _headers_to_dict(e.headers)
                try:
                    body = e.read(MAX_BODY_BYTES).decode("utf-8", "replace")
                except Exception:
                    body = ""
                return {"url": url, "final_url": cur, "status": e.code,
                        "headers": hdrs, "body": body, "set_cookies": cookies,
                        "error": None, "redirects": hops}
        return {"url": url, "final_url": cur, "status": None, "headers": {}, "body": None,
                "set_cookies": [], "error": f"too many redirects (> {MAX_REDIRECTS})",
                "redirects": hops}
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as e:
        return {"url": url, "final_url": cur, "status": None, "headers": {}, "body": None,
                "set_cookies": [], "error": f"{type(e).__name__}: {e}", "redirects": hops}


# --------------------------------------------------------------------------
# payload construction — cors.md §2 bypass table, verbatim logic
# --------------------------------------------------------------------------

def parse_target(target: str) -> tuple[str, str, str] | None:
    """'https://api.target.com/endpoint' -> (scheme, netloc, 'https://api.target.com').
    A bare host gets https:// prepended (deterministic; documented in the CLI help).
    None if the result has no http(s) scheme or no host."""
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    p = urllib.parse.urlsplit(t)
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return p.scheme, p.netloc, f"{p.scheme}://{p.netloc}"


def build_origin_payloads(netloc: str, scheme: str) -> list:
    """The cors.md §2 bypass table instantiated with the reserved attacker placeholder.
    Ordered by the doc's yield order; names are stable identifiers used in metadata."""
    a = ATTACKER_PLACEHOLDER

    def P(name: str, origin: str) -> dict:
        return {"name": name, "origin": origin}

    payloads = [
        P("arbitrary", "https://" + a),                      # §1 pure-reflection probe
        P("suffix", f"https://{netloc}.{a}"),                # endsWith / naive contains
        P("prefix_raw", f"https://{a}{netloc}"),             # startsWith-style, no separator
        P("prefix_dashes", f"https://{a}{netloc.replace('.', '-')}"),
        P("subdomain", f"https://{SUBDOMAIN_PROBE_LABEL}.{netloc}"),  # *.target.com wildcard?
        P("underscore", f"https://{netloc.replace('.', '_', 1)}.{a}"),  # regex '.' loose match
        P("underscore_tail", f"https://{netloc}_.{a}"),
        P("safari_brace", f"https://{netloc}{{.{a}"),        # Safari { } ` domain-split (§2)
        P("safari_brace_close", f"https://{netloc}}}.{a}"),
        P("safari_backtick", f"https://{netloc}`.{a}"),
    ]
    if scheme == "https":
        payloads.append(P("scheme_downgrade", "http://" + netloc))
    payloads += [
        P("userinfo_pass", f"https://{netloc}:evilpass@{a}"),
        P("userinfo_plain", f"https://{netloc}@{a}"),        # userinfo confusion
        P("null", "null"),                                   # dev-leftover null allowlist (§3)
    ]
    return payloads


def dot_mutants(netloc: str, chars=MUTATION_CHARS) -> list:
    """cors.md §2b's awk loop, reimplemented: for EACH dot position, replace just that one
    dot with the mutation char and keep the rest of the hostname intact. Deduped in order
    (different positions/chars can collapse onto the same string)."""
    out, seen = [], set()
    for sub in chars:                       # cors.md: "for sub in x - a _" (chars outer)
        for n in range(1, netloc.count(".") + 1):   # ...then each dot position in turn
            c, host = 0, []
            for ch in netloc:
                if ch == ".":
                    c += 1
                    host.append(sub if c == n else ch)
                else:
                    host.append(ch)
            mutant = "".join(host)
            if mutant in seen:
                continue
            seen.add(mutant)
            out.append({"host": mutant, "dot_position": n, "char": sub})
    return out


# --------------------------------------------------------------------------
# classification — cors.md §1 decision table, row for row
# --------------------------------------------------------------------------

def looks_like_regex(acao: str) -> bool:
    return bool(REGEXISH_RE.search(acao))


def classify(payload_origin: str, acao: str | None, acac: str | None) -> str:
    """cors.md §1's decision table for one (payload -> response) pair."""
    acao_n = (acao or "").strip()
    if not acao_n:
        return CLASS_NO_ACAO
    acac_true = (acac or "").strip().lower() == "true"
    if payload_origin.lower() == "null":
        if acao_n.lower() == "null":
            return CLASS_VULN_NULL if acac_true else CLASS_NULL_NO_CREDS
    elif acao_n.lower() == payload_origin.lower():
        return CLASS_VULN if acac_true else CLASS_NO_CREDS  # verbatim reflection (§2's rule)
    if acao_n == "*":
        return CLASS_WILDCARD_CREDS if acac_true else CLASS_WILDCARD
    if looks_like_regex(acao_n):
        return CLASS_REGEX
    return CLASS_ALLOWLIST


def parse_samesite(set_cookies: list) -> list:
    """Cookie NAMES + SameSite attr per Set-Cookie header. Values are never recorded
    (they are credentials; no secrets in evidence — house rule)."""
    out = []
    for raw in set_cookies or []:
        first = raw.split(";", 1)[0]
        name = first.split("=", 1)[0].strip()
        samesite = None
        for attr in raw.split(";")[1:]:
            if "=" in attr:
                k, v = attr.split("=", 1)
                if k.strip().lower() == "samesite":
                    samesite = v.strip().capitalize()  # lax->Lax, none->None, strict->Strict
        out.append({"name": name, "samesite": samesite})
    return out


def samesite_note(observed: str | None) -> str:
    """cors.md §4: SameSite is the gate that decides real-world impact."""
    if observed == "None":
        return ("SameSite=None observed — the cookie rides cross-site; the reflections above "
                "are at FULL practical severity (cors.md §4)")
    if observed == "Strict":
        return ("SameSite=Strict observed — the cookie never rides cross-site; a CORS "
                "reflection alone cannot exfiltrate authenticated data (cors.md §4)")
    if observed == "Lax":
        return ("SameSite=Lax observed — the cookie will NOT ride a cross-site fetch/XHR, so "
                "cross-site (different registrable domain) reflections are downgraded in "
                "practical severity: a same-site (*.<target>-scoped) reflection is the "
                "stronger lead (cors.md §4)")
    return ("no SameSite attribute observed — modern Chrome/Firefox default to Lax, so treat "
            "as Lax: cross-site reflections downgraded, a same-site reflection is the "
            "stronger lead (cors.md §4)")


# --------------------------------------------------------------------------
# next_action language (the ONE RULE lives here — every VULNERABLE-tier verdict carries it)
# --------------------------------------------------------------------------

PRECONDITION_TAIL = (
    "Per SKILL.md this is a PRECONDITION, not a finding on its own — and a header-behavior "
    "check can never emit CONFIRMED: before reporting you must (1) replay with your own auth "
    "and confirm the body carries real money/PII/creds (a real cross-origin read of YOUR "
    "data, cors.md §7), (2) have a delivery vector in hand — same-site XSS / subdomain "
    "takeover / attacker-controlled subdomain (cors.md §3/§5), and (3) re-check SameSite on "
    "the session cookie (cors.md §4)")

VULN_NEXT_ACTION = (
    "Status: LIKELY, never CONFIRMED from this tool — a reflected attacker origin with "
    "ACAC:true is the strongest header-level signal there is, but exploitation needs the "
    "data + delivery verification. " + PRECONDITION_TAIL)

NULL_NEXT_ACTION = (
    "Status: LIKELY, never CONFIRMED from this tool — null-origin reflection with ACAC:true "
    "is exploitable from a sandboxed data: iframe and needs NO attacker-controlled domain "
    "(cors.md §3), but the same data + delivery verification still applies. " + PRECONDITION_TAIL)

DOT_NEXT_ACTION = (
    "Status: LIKELY at reduced confidence — the allowlist regex has an unescaped dot at the "
    "reflected position(s), but whether the implied domain is actually registrable was NOT "
    "verified (this script deliberately does not query RDAP/WHOIS from inside a test run): "
    "verify the implied domain(s) (e.g. via RDAP, cors.md §2b) are unregistered BEFORE "
    "treating this as exploitable, then re-rate with SameSite in mind (cross-site mutants "
    "are downgraded under Lax; a same-site *.target.com match is the stronger lead). " +
    PRECONDITION_TAIL)

NO_CREDS_NEXT_ACTION = (
    "Low lead only — reflection without ACAC:true means browsers will not attach cookies "
    "(cors.md THE ONE RULE), so no cookie theft; it only escalates if the endpoint returns "
    "public-but-sensitive data or readable-without-cookies auth material. Check what the "
    "response body actually carries before spending more time. Still LIKELY, never CONFIRMED.")

WILDCARD_CREDS_NEXT_ACTION = (
    "Not exploitable — do not report as a CORS vuln: the Fetch spec forbids ACAO:* together "
    "with credentials mode 'include', so browsers reject the response in credentialed mode. "
    "Record as a config smell only (cors.md §1).")

WILDCARD_NEXT_ACTION = (
    "Public-data exposure at most — ACAO:* without credentials cannot read authenticated "
    "data (browsers won't send cookies); only interesting if the endpoint's data is itself "
    "sensitive-but-public (cors.md §1).")

CLEAN_NEXT_ACTION = (
    "Not vulnerable on this endpoint as of this run — no tested origin was reflected and "
    "the fixed allowlist survived both the cors.md §2 bypass table and the §2b unescaped-dot "
    "sweep. Record as tested-and-clean in coverage.md (distinct from untested); re-test "
    "after gateway changes and on sibling routes — CORS config is often PER-ROUTE, not "
    "per-host (cors.md §6/§8).")

UNREACHABLE_NEXT_ACTION = (
    "target unreachable from here (transport-level failure) — confirm the host is live and "
    "in-scope before re-testing; no CORS verdict is possible from this run")


# --------------------------------------------------------------------------
# the pipeline
# --------------------------------------------------------------------------

def _probe_request(url: str, timeout: float, method: str, origin: str | None,
                   auth: dict, extra: dict | None = None,
                   requests_made: list | None = None) -> dict:
    headers = dict(auth)
    if origin is not None:
        headers["Origin"] = origin
    if extra:
        headers.update(extra)
    r = http_probe(url, timeout, method, headers)
    if requests_made is not None:
        o = f" [Origin: {origin}]" if origin is not None else " (no Origin — baseline)"
        requests_made.append(f"{method} {url}{o}")
    return r


def scan_target(target: str, timeout: float = DEFAULT_TIMEOUT, cookie: str | None = None,
                extra_headers: dict | None = None, verbose: bool = False) -> dict:
    """Full 3-stage pipeline for one target; returns the normalized result object.
    Never raises: per-request failures degrade into errors[] (one bad request must never
    abort the sweep, one bad target must never abort the run)."""
    evidence: list = []
    errors: list = []
    requests_made: list = []

    def ev(msg: str) -> None:
        evidence.append(msg)
        if verbose:
            eprint(f"  [{target}] {msg}")

    def finish(findings: list, metadata: dict) -> dict:
        return {"tool": TOOL, "target": target, "timestamp": now_iso(), "status": "success",
                "findings": findings, "evidence": list(evidence), "errors": list(errors),
                "metadata": metadata}

    def finding(severity: str, confidence: float, ev_lines: list,
                next_action: str, variant: str | None = None) -> dict:
        f = {"type": "cors_misconfig", "severity": severity, "confidence": confidence,
             "target": target, "evidence": ev_lines, "source": SOURCE,
             "next_action": next_action}
        if variant:
            f["variant"] = variant
        return f

    auth = dict(extra_headers or {})
    if cookie:
        auth["Cookie"] = cookie

    parsed = parse_target(target)
    if parsed is None:
        errors.append(f"invalid target URL (need scheme + host): {target}")
        return finish([finding("info", CONF_UNREACHABLE,
                               ["target URL could not be parsed — no scheme/host"],
                               UNREACHABLE_NEXT_ACTION, variant="unreachable")],
                      {"legitimate_origin": None, "payload_results": [], "requests_made": requests_made})
    scheme, netloc, legitimate_origin = parsed
    ev(f"target {target} — legitimate origin {legitimate_origin} "
       f"(attacker placeholder: {ATTACKER_PLACEHOLDER}, RFC 2606 reserved — never resolved)")

    # ---- stage 0: baseline (auth replayed, no Origin) -> status + Set-Cookie SameSite ----
    baseline = _probe_request(target, timeout, "GET", None, auth, requests_made=requests_made)
    if baseline["error"] is not None:
        ev(f"baseline: transport failure ({baseline['error']}) — sweeping anyway; every "
           f"failed request is recorded, the verdict stays INCONCLUSIVE")
        errors.append(f"baseline GET failed: {baseline['error']}")
    else:
        ev(f"baseline: HTTP {baseline['status']} | ACAO: "
           f"{baseline['headers'].get('access-control-allow-origin', '(absent)')} | ACAC: "
           f"{baseline['headers'].get('access-control-allow-credentials', '(absent)')}")
    samesite_cookies = parse_samesite(baseline.get("set_cookies"))
    observed_samesite = next((c["samesite"] for c in samesite_cookies if c["samesite"]), None)
    ev("samesite: " + samesite_note(observed_samesite))

    # ---- stage 1: cors.md §1 probe + §2 bypass-payload sweep ---------------------------
    payload_results: list = []
    for p in build_origin_payloads(netloc, scheme):
        r = _probe_request(target, timeout, "GET", p["origin"], auth,
                           requests_made=requests_made)
        if r["error"] is not None:
            entry = {"name": p["name"], "origin": p["origin"], "status": None,
                     "acao": None, "acac": None, "reflected": False,
                     "classification": CLASS_ERROR, "error": r["error"]}
            errors.append(f"payload {p['name']} (Origin: {p['origin']}): {r['error']}")
            ev(f"payload {p['name']}: FAILED ({r['error']}) — sweep continues")
        else:
            acao = r["headers"].get("access-control-allow-origin")
            acac = r["headers"].get("access-control-allow-credentials")
            cls = classify(p["origin"], acao, acac)
            entry = {"name": p["name"], "origin": p["origin"], "status": r["status"],
                     "acao": acao, "acac": acac, "reflected": cls in REFLECTING_CLASSES,
                     "classification": cls, "error": None}
            ev(f"payload {p['name']}: HTTP {r['status']} | ACAO: {acao or '(absent)'} | "
               f"ACAC: {acac or '(absent)'} -> {cls}")
        payload_results.append(entry)

    reflecting = [e for e in payload_results if e["reflected"]]
    vuln = [e for e in reflecting if e["classification"] in (CLASS_VULN, CLASS_VULN_NULL)]
    no_creds = [e for e in reflecting if e["classification"] in (CLASS_NO_CREDS, CLASS_NULL_NO_CREDS)]
    regex_echoes = [(e["origin"], e) for e in payload_results
                    if e["classification"] == CLASS_REGEX]
    wildcard_creds_seen = any(e["classification"] == CLASS_WILDCARD_CREDS for e in payload_results)
    wildcard_seen = wildcard_creds_seen or any(e["classification"] == CLASS_WILDCARD for e in payload_results)

    # ---- preflight (cors.md §2b) — best reflecting origin, else the legitimate one ------
    best = next((e for cls in PREFLIGHT_PRIORITY for e in payload_results
                 if e["classification"] == cls), None)
    pre_origin = best["origin"] if best is not None else legitimate_origin
    pre_extra = {"Access-Control-Request-Method": "GET"}
    if extra_headers:
        pre_extra["Access-Control-Request-Headers"] = ", ".join(extra_headers.keys())
    pre = _probe_request(target, timeout, "OPTIONS", pre_origin, auth, pre_extra,
                         requests_made=requests_made)
    if pre["error"] is not None:
        preflight_meta = {"origin": pre_origin, "status": None, "acao": None, "acac": None,
                          "consistent_with_simple": None,
                          "advertised_request_headers": sorted((extra_headers or {}).keys()),
                          "note": f"preflight request failed: {pre['error']}"}
        errors.append(f"preflight OPTIONS failed: {pre['error']}")
        ev(f"preflight: FAILED ({pre['error']})")
    else:
        pre_acao = pre["headers"].get("access-control-allow-origin")
        pre_acac = pre["headers"].get("access-control-allow-credentials")
        if best is not None:  # the simple request reflected an attacker origin — does OPTIONS?
            pre_reflected = classify(pre_origin, pre_acao, pre_acac) in REFLECTING_CLASSES
            consistent = pre_reflected
            if pre_reflected:
                note = ("preflight honors the same allowlist as the simple request — "
                        "non-simple verbs work too (cors.md §2b)")
            else:
                note = ("INCONSISTENT — the simple request reflects this origin but the "
                        "preflight does not: non-simple verbs (PUT/DELETE/...) are killed "
                        "even if GET-based theft still works (cors.md §2b)")
        else:  # nothing reflected on simple; the preflight used the legitimate origin
            echoed_self = ((pre_acao or "").strip().lower() == legitimate_origin.lower())
            consistent = True
            note = ("preflight answers and echoes the legitimate origin (self allowed — "
                    "expected); consistent with stage 1: no attacker-origin reflection on "
                    "either path (cors.md §2b)" if echoed_self else
                    f"preflight answers with ACAO: {pre_acao or '(absent)'} — no "
                    f"attacker-origin reflection on either path (cors.md §2b)")
        preflight_meta = {"origin": pre_origin, "status": pre["status"], "acao": pre_acao,
                          "acac": pre_acac, "consistent_with_simple": consistent,
                          "advertised_request_headers": sorted((extra_headers or {}).keys()),
                          "note": note}
        ev(f"preflight (OPTIONS, ACRM: GET, Origin: {pre_origin}): HTTP {pre['status']} | "
           f"ACAO: {pre_acao or '(absent)'} | ACAC: {pre_acac or '(absent)'} — {note}")

    # ---- stage 2: cors.md §2b unescaped-dot sweep (ADAPTIVE trigger) --------------------
    stage2 = {"triggered": False, "reason": "", "mutants": [],
              "reflecting_with_credentials": [], "reflecting_without_credentials": []}
    if reflecting:
        stage2["reason"] = ("skipped — stage 1 already reflected attacker-controlled "
                            "origin(s); naive reflection beats regex-escape probing")
    elif wildcard_seen:
        stage2["reason"] = ("skipped — wildcard ACAO observed; there is no host allowlist "
                            "regex to escape (§2b applies to hand-rolled allowlists)")
    elif all(e["error"] is not None for e in payload_results):
        stage2["reason"] = "skipped — no usable response from the target (transport failures)"
    else:
        stage2["triggered"] = True
        stage2["reason"] = ("stage 1: fixed allowlist, zero attacker-origin reflections — "
                            "probing it for unescaped dots (cors.md §2b)")
        ev("stage2: " + stage2["reason"])
        for m in dot_mutants(netloc):
            origin = f"{scheme}://{m['host']}"
            r = _probe_request(target, timeout, "GET", origin, auth,
                               requests_made=requests_made)
            if r["error"] is not None:
                entry = {**m, "origin": origin, "status": None, "acao": None, "acac": None,
                         "reflected": False, "classification": CLASS_ERROR, "error": r["error"]}
                errors.append(f"dot-mutant {m['host']}: {r['error']}")
                ev(f"stage2 mutant {m['host']}: FAILED ({r['error']})")
            else:
                acao = r["headers"].get("access-control-allow-origin")
                acac = r["headers"].get("access-control-allow-credentials")
                cls = classify(origin, acao, acac)
                entry = {**m, "origin": origin, "status": r["status"], "acao": acao,
                         "acac": acac, "reflected": cls in REFLECTING_CLASSES,
                         "classification": cls, "error": None}
                ev(f"stage2 mutant {m['host']}: HTTP {r['status']} | "
                   f"ACAO: {acao or '(absent)'} | ACAC: {acac or '(absent)'} -> {cls}")
            stage2["mutants"].append(entry)
            if entry["classification"] in (CLASS_VULN, CLASS_VULN_NULL):
                stage2["reflecting_with_credentials"].append(entry)
            elif entry["classification"] in (CLASS_NO_CREDS, CLASS_NULL_NO_CREDS):
                stage2["reflecting_without_credentials"].append(entry)

    # ---- verdict assembly ---------------------------------------------------------------
    base_ctx = [
        f"baseline GET -> HTTP {baseline['status']}" if baseline["error"] is None
        else f"baseline GET failed at transport level ({baseline['error']})",
        f"{len(payload_results)} payload origin(s) tested against {target} "
        f"(cors.md §1 probe + §2 bypass table)",
        "preflight: " + preflight_meta["note"],
    ]

    if vuln:
        ev_lines = base_ctx[:]
        for e in vuln:
            tag = ("null origin — exploitable from a sandboxed data: iframe, no "
                   "attacker-controlled domain needed (cors.md §3)"
                   if e["classification"] == CLASS_VULN_NULL
                   else "reflected attacker origin (cors.md §1/§2)")
            ev_lines.append(f"VULNERABLE-class: Origin: {e['origin']} -> ACAO: {e['acao']} | "
                            f"ACAC: {e['acac']} (HTTP {e['status']}) — {tag}")
        if no_creds:
            ev_lines.append(f"also reflected WITHOUT credentials: "
                            f"{', '.join(e['origin'] for e in no_creds)}")
        ev_lines.append("SameSite: " + samesite_note(observed_samesite))
        if wildcard_creds_seen:
            ev_lines.append("note: ACAO:* + ACAC:true was also observed somewhere in the "
                            "sweep — spec-rejected (browsers reject wildcard+credentials), "
                            "irrelevant to the exploitable reflections above")
        primary = finding("medium", CONF_VULN, ev_lines,
                          NULL_NEXT_ACTION if all(e["classification"] == CLASS_VULN_NULL
                                                  for e in vuln) else VULN_NEXT_ACTION,
                          variant="reflected_origin_with_credentials")
    elif stage2["reflecting_with_credentials"]:
        hits = stage2["reflecting_with_credentials"]
        ev_lines = base_ctx[:]
        ev_lines.append(f"unescaped-dot sweep (cors.md §2b): {len(hits)} of "
                        f"{len(stage2['mutants'])} mutants reflected with ACAC:true — the "
                        f"allowlist regex has an unescaped '.' at the mutated position(s)")
        for e in hits:
            ev_lines.append(f"reflected mutant: Origin: {e['origin']} -> ACAO: {e['acao']} | "
                            f"ACAC: {e['acac']} (dot {e['dot_position']} -> '{e['char']}')")
        ev_lines.append("whether the implied registrable domain(s) are actually registrable "
                        "is UNVERIFIED — verify via RDAP/WHOIS before treating as real "
                        "(cors.md §2b two-step methodology)")
        if stage2["reflecting_without_credentials"]:
            ev_lines.append("weaker: also reflected without credentials: "
                            + ", ".join(e["origin"] for e in stage2["reflecting_without_credentials"]))
        ev_lines.append("SameSite: " + samesite_note(observed_samesite))
        primary = finding("medium", CONF_DOT, ev_lines, DOT_NEXT_ACTION,
                          variant="unescaped_dot_allowlist")
    elif no_creds:
        ev_lines = base_ctx[:]
        for e in no_creds:
            tag = ("null origin, no credentials" if e["classification"] == CLASS_NULL_NO_CREDS
                   else "reflected, no credentials")
            ev_lines.append(f"reflection WITHOUT credentials: Origin: {e['origin']} -> "
                            f"ACAO: {e['acao']} (HTTP {e['status']}) — {tag}")
        ev_lines.append("no cookie theft: browsers do not attach cookies without "
                        "ACAC:true (cors.md THE ONE RULE)")
        ev_lines.append("SameSite: " + samesite_note(observed_samesite))
        primary = finding("low", CONF_NO_CREDS, ev_lines, NO_CREDS_NEXT_ACTION,
                          variant="reflected_origin_without_credentials")
    elif wildcard_creds_seen:
        primary = finding("info", CONF_WILDCARD_CREDS, base_ctx[:] + [
            "ACAO:* observed together with ACAC:true — the Fetch spec forbids wildcard+"
            "credentials, so browsers REJECT the response in credentialed mode: not "
            "exploitable, note-only (cors.md §1)",
            "SameSite: " + samesite_note(observed_samesite)],
            WILDCARD_CREDS_NEXT_ACTION, variant="wildcard_with_credentials")
    elif wildcard_seen:
        primary = finding("info", CONF_WILDCARD, base_ctx[:] + [
            "ACAO:* (no credentials) — public data only; browsers will not attach cookies "
            "to a cross-origin request the server answers with a wildcard (cors.md §1)",
            "SameSite: " + samesite_note(observed_samesite)],
            WILDCARD_NEXT_ACTION, variant="wildcard_public")
    elif stage2["triggered"]:
        clean_lines = [
            "no tested origin was reflected (exact-match/fixed allowlist)",
            f"unescaped-dot sweep (cors.md §2b) ran: {len(stage2['mutants'])} mutants, "
            f"0 reflected — the allowlist survived",
        ]
        if regex_echoes:
            clean_lines.append("note: the allowlist leaked its raw regex on miss — see the "
                               "companion allowlist_regex_disclosed finding")
        if errors:
            clean_lines.append(f"note: {len(errors)} request(s) failed during the sweep — "
                               f"those origins are untested this run (see errors)")
        clean_lines.append("SameSite: " + samesite_note(observed_samesite))
        primary = finding("info", CONF_CLEAN, base_ctx[:] + clean_lines,
                          CLEAN_NEXT_ACTION, variant="not_vulnerable")
    else:
        primary = finding("info", CONF_UNREACHABLE, base_ctx[:] + [
            "no usable HTTP response from any payload (transport-level failures) — "
            "INCONCLUSIVE, not a clean bill of health"],
            UNREACHABLE_NEXT_ACTION, variant="unreachable")

    findings = [primary]
    if regex_echoes:
        lines = [f"raw regex echoed back as Access-Control-Allow-Origin (hand-rolled CORS, "
                 f"allowlist disclosed — cors.md §1 last row): \"{e['acao']}\" "
                 f"(in response to Origin: {o}, HTTP {e['status']})"
                 for o, e in regex_echoes]
        lines.append("the regex leak itself is a separate info-disclosure finding, distinct "
                     "from whether the allowlist is also exploitable")
        findings.append(finding("low", CONF_REGEX, lines,
                                "enumerate the leaked allowlist (cors.md §1: 'allowlist "
                                "disclosed + hand-rolled CORS — enumerate it'); the regex "
                                "pattern itself is the disclosure — check it for the same "
                                "unescaped-dot bugs cors.md §2b describes"))

    return finish(findings, {
        "timeout_s": timeout,
        "legitimate_origin": legitimate_origin,
        "attacker_placeholder": ATTACKER_PLACEHOLDER,
        "auth_replayed": {"cookie": bool(cookie),
                          "headers": sorted((extra_headers or {}).keys())},
        "baseline": {"status": baseline["status"],
                     "acao": baseline["headers"].get("access-control-allow-origin"),
                     "acac": baseline["headers"].get("access-control-allow-credentials"),
                     "error": baseline["error"]},
        "samesite": {"observed": observed_samesite,
                     "source": "Set-Cookie of the baseline response",
                     "note": samesite_note(observed_samesite),
                     "cookies": samesite_cookies},
        "payload_results": payload_results,
        "stage2_dot_sweep": stage2,
        "preflight": preflight_meta,
        "requests_made": requests_made,
    })


# --------------------------------------------------------------------------
# CLI (conventions shared with cms_detect.py / js_recon.py)
# --------------------------------------------------------------------------

def load_target_list(path: str) -> list:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"list file not found: {path}")
    out = []
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln)
    return out


def parse_header_args(pairs: list) -> dict:
    """'Name: value' (repeatable) -> dict. Hard usage error on a malformed pair."""
    out = {}
    for raw in pairs or []:
        if ":" not in raw:
            raise ValueError(f"malformed --header (expected 'Name: value'): {raw}")
        name, value = raw.split(":", 1)
        name, value = name.strip(), value.strip()
        if not name or not value:
            raise ValueError(f"malformed --header (expected 'Name: value'): {raw}")
        out[name] = value
    return out


def print_human(results: list, quiet: bool) -> None:
    if quiet:
        return
    for r in results:
        f = r["findings"][0] if r["findings"] else None
        if f:
            ss = r["metadata"].get("samesite", {}).get("observed")
            pre = r["metadata"].get("preflight", {})
            eprint(f"[{r['target']}] {f['severity'].upper()}/{f.get('variant', 'cors_misconfig')} "
                   f"(confidence {f['confidence']}): {f['next_action'].split('.')[0]}")
            eprint(f"[{r['target']}] {len(r['metadata'].get('payload_results', []))} payload(s) "
                   f"tested | SameSite: {ss or 'not observed'} | preflight consistent: "
                   f"{pre.get('consistent_with_simple')}")
        for err in r["errors"]:
            eprint(f"[{r['target']}] ERROR: {err}")
    eprint("")
    eprint("Next: for any medium/LIKELY verdict, verify the endpoint returns real sensitive "
           "data to YOUR own session cross-origin and find the delivery vector (cors.md "
           "§3/§5) before reporting — a header reflection alone is a precondition, not a "
           "finding; record clean targets as tested-and-clean in coverage.md")


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=SOURCE,
        description="Credentialed-CORS misconfiguration checker (cors.md pipeline): baseline "
                    "+ Origin bypass-payload sweep (§1 decision table + §2 table), adaptive "
                    "unescaped-dot allowlist sweep (§2b), preflight consistency check, and "
                    "SameSite discipline (§4). Verdicts cap at LIKELY — a credentialed-CORS "
                    "reflection is a precondition, never a standalone finding (SKILL.md).",
        epilog="examples:\n"
               "  %(prog)s https://target.example/api/endpoint\n"
               "  %(prog)s https://target.example/api/account --cookie \"SESSION=<value>\"\n"
               "  %(prog)s -l recon/live.txt --json --output cors.json --threads 20\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", metavar="target",
                    help="target URL(s) — a specific endpoint behind auth is ideal "
                         "(bare hosts get https:// prepended)")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file of target URLs, one per line (# comments allowed)")
    ap.add_argument("--cookie", metavar="VALUE",
                    help="raw Cookie header value replayed on every request "
                         "(e.g. \"SESSION=<victim>\")")
    ap.add_argument("-H", "--header", dest="headers", action="append", metavar="NAME: VALUE",
                    help="extra header to replay on every request, repeatable "
                         "(e.g. \"Authorization: Bearer <token>\")")
    ap.add_argument("--json", action="store_true",
                    help="machine output on stdout (normalized JSON; array when >1 target)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SEC",
                    help="per-HTTP-operation timeout in seconds (default: 5)")
    ap.add_argument("--threads", type=int, default=DEFAULT_THREADS, metavar="N",
                    help="concurrent workers for the outer loop over multiple targets "
                         "(default: 10; the per-target sweep stays sequential)")
    ap.add_argument("--output", metavar="FILE",
                    help="also write the JSON result(s) to this file")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress the human-readable summary (no effect with --json)")
    ap.add_argument("--verbose", action="store_true",
                    help="print each request's evidence to stderr as it runs")
    args = ap.parse_args(argv)

    targets = list(args.targets)
    if args.list:
        try:
            targets.extend(load_target_list(args.list))
        except (OSError, FileNotFoundError) as e:
            eprint(f"[!] {e}")
            return 2
    targets = [t for t in (t.strip() for t in targets) if t]
    if not targets:
        ap.error("no targets given (positional args or -l/--list FILE)")
    if args.timeout <= 0:
        ap.error("--timeout must be > 0")
    if args.threads < 1:
        ap.error("--threads must be >= 1")
    try:
        extra_headers = parse_header_args(args.headers)
    except ValueError as e:
        ap.error(str(e))

    if not args.quiet and not args.json:
        eprint(f"[*] {TOOL}: {len(targets)} target(s) | attacker placeholder: "
               f"{ATTACKER_PLACEHOLDER} (never resolved) | auth replayed: "
               f"cookie={bool(args.cookie)}, headers={sorted(extra_headers)} "
               f"| timeout: {args.timeout}s | pure stdlib HTTP")

    def run_one(t: str) -> dict:
        try:
            return scan_target(t, timeout=args.timeout, cookie=args.cookie,
                               extra_headers=extra_headers, verbose=args.verbose)
        except Exception as e:  # never let one target kill the run
            return {"tool": TOOL, "target": t, "timestamp": now_iso(), "status": "success",
                    "findings": [], "evidence": [],
                    "errors": [f"unexpected error: {type(e).__name__}: {e}"],
                    "metadata": {"timeout_s": args.timeout}}

    if len(targets) == 1:
        results = [run_one(targets[0])]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, len(targets))) as ex:
            futures = {ex.submit(run_one, t): t for t in targets}
            by_target = {}
            for fut in concurrent.futures.as_completed(futures):
                by_target[futures[fut]] = fut.result()
            results = [by_target[t] for t in targets]  # preserve input order

    payload = results[0] if len(results) == 1 else results
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_human(results, quiet=args.quiet)

    if args.output:
        try:
            Path(args.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            if not args.quiet and not args.json:
                eprint(f"[*] JSON written to {args.output}")
        except OSError as e:
            eprint(f"[!] failed to write {args.output}: {e}")
            return 2

    return 0  # completed scan — exit non-zero only for hard errors above


if __name__ == "__main__":
    sys.exit(main())
