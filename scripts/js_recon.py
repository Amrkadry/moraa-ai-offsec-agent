#!/usr/bin/env python3
"""js_recon.py — JS bundle miner: range-parallel download, secrets/endpoints/source-map
recon over a recon/js.txt-style list (zero pip deps).

WHY: js-analysis.md is the repo's single highest-yield recon step — the frontend host is
static, the real backend hosts, route list, secrets and runtime config all live in the
bundle — and until now it was pure manual bash loops. This script automates that doc's
pipeline, section by section:

    JS URL LIST -> SIZE/RANGE PROBE -> DOWNLOAD (range-parallel or single, size-asserted)
                -> SECRETS/KEYS (js-analysis.md §2 regex set + runtime-config vars)
                -> HOSTS / API PATHS / SPA ROUTES (§3)
                -> SOURCE-MAP PROBE (<url>.map, parse-confirmed, CWE-540)
                -> DEDUPED AGGREGATE (one result object for the whole batch)

Range-parallel download (js-analysis.md §1's exact lesson): huge bundles (10 MB+) pulled
in one stream get silently truncated by throttling/RST'ing origins (the 35.5 MB the NMS appliance
bundle stalled at ~11 MB: 74 routes in the partial vs 293 in the full copy — the actual
SSRF-candidate endpoint only existed in the complete file). So: probe `Accept-Ranges:
bytes` + Content-Length with a HEAD first (1-byte ranged GET fallback for HEAD-hostile
CDNs — a 206's Content-Range carries the total); any bundle >= --chunk-threshold-mb
(default 2) WITH range support is pulled in --range-chunks (default 12, the doc's
example) parallel byte-range chunks and reassembled in order; everything else (small
bundle, no range support) gets one plain bounded GET. EITHER WAY the assembled byte
length is asserted against the declared Content-Length — a mismatch is a distinct
TRUNCATED_DOWNLOAD error state and the bundle is NOT mined. A silently-short pull is a
false-negative factory; reporting "no secrets" off a partial bundle would be worse than
reporting nothing.

Severity/confidence discipline (this repo never over-claims from one weak signal):
- js_secret findings are regex PATTERN matches only, never verified live. Severity is
  capped at "medium" (high-confidence tier), "low" (medium tier: AWS access-key IDs,
  which are identifiers and usually pair with a separately-placed secret) or "info"
  (low tier: AIza/ya29/firebase, often restricted or public-by-design). Never
  "high"/"critical" — that jump requires the validate.md gate and live verification
  this script cannot do. A match may equally be a bundled example/placeholder value.
- js_sourcemap_exposure is severity "low" (CWE-540 info disclosure) and only after the
  .map body is CONFIRMED parseable JSON carrying "sources"/"sourcesContent" — a 200
  with an HTML error page at that path is not a source map. Recovering worse findings
  from the reconstructed source is manual follow-up, out of scope here (see
  next_action on the finding).
- js_endpoint_summary is severity "info": the aggregated host/endpoint/route lists are
  recon output, not a vulnerability.

Scope discipline: run against in-scope bundles only. Every request is a read-only GET/HEAD.

HTTP client: adapted from cms_detect.probe_http (bounded reads, capped hop-logged
redirect-following, TLS verify off for intercepting proxies — same precedent as its
siblings; no requests/urllib3). TWO deliberate differences from the sibling recon
clients, both required by this script's job:
- BODY CAP: subdomain_takeover.py/cms_detect.py cap bodies at 64KB because fingerprint
  pages are tiny. This script's whole purpose is reading whole JS bundles (tens of MB),
  so its cap is MAX_BUNDLE_BYTES (512 MB, a runaway-response guard, not a fingerprint
  cap) and, because a silently-capped read would defeat the size assertion above, an
  over-cap read is reported as an explicit error instead of being quietly truncated.
- BODY TYPE: bytes, not decoded text — chunk reassembly and the Content-Length assertion
  are byte-exact; decoding to text with errors="replace" happens only after the size
  check, at mining time.

Zero pip dependencies by design (rationale documented in the sibling docstrings —
scripts/subdomain_takeover.py / scripts/cms_detect.py). Pure stdlib HTTP; no external
binary, no find_tool() seam. Python 3.8+ (annotations are strings via __future__).

Usage:
    python3 js_recon.py https://host/app.min.js [more.js ...]
    python3 js_recon.py -l recon/js.txt --json --output js_recon.json
    python3 js_recon.py -l recon/js.txt --range-chunks 16 --chunk-threshold-mb 5
    python3 js_recon.py https://host/app.min.js --verbose   # per-stage evidence to stderr

Exit code: 0 for a completed scan (zero secrets/maps found, or every bundle failing, is
still a completed scan — failures land in errors[]), non-zero only for hard errors (bad
args, missing/unreadable -l file).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TOOL = "js_recon"
SOURCE = "js_recon.py"

USER_AGENT = "Mozilla/5.0 (compatible; moraa-jsrecon/1.0; authorized-scope-use-only)"
MAX_REDIRECTS = 4  # hop-logged, then give up (cms_detect.probe_http precedent)

# WHY 512MB and not the siblings' 64KB: subdomain_takeover.py/cms_detect.py fingerprint
# tiny pages, so a 64KB cap is right there. This script's purpose is mining whole JS
# bundles — capping at 64KB would guarantee the exact truncated-pull false negatives
# js-analysis.md §1 warns about. 512MB is a runaway-response guard only; reads beyond it
# are an explicit error (never a quiet cap), see MAX_BUNDLE_BYTES handling in http_fetch.
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
# Source maps can also be large (sourcesContent embeds full original sources) but are
# bounded harder: they only need to parse as JSON to confirm exposure.
MAX_SOURCEMAP_BYTES = 64 * 1024 * 1024

DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 10            # OUTER loop: bundles fetched concurrently
DEFAULT_RANGE_CHUNKS = 12       # INNER: parallel byte-range chunks per large bundle (js-analysis.md §1 example)
DEFAULT_CHUNK_THRESHOLD_MB = 2.0
CHUNK_RETRIES = 2               # extra attempts per chunk before declaring truncation


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# HTTP fetch (single network seam — adapted from cms_detect.probe_http: bounded
# reads, capped hop-logged redirects, TLS verify off for intercepting proxies;
# bytes bodies + over-cap detection instead of the siblings' 64KB decoded cap —
# see the MAX_BUNDLE_BYTES comment above for why this script differs)
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


def _headers_to_dict(hdrs) -> dict:
    return {k.lower(): v for k, v in hdrs.items()}


def http_fetch(url: str, timeout: float, method: str = "GET",
               extra_headers: dict | None = None, max_bytes: int | None = None) -> dict:
    """One bounded request (HEAD/GET). Redirects followed up to MAX_REDIRECTS (each hop
    logged). Returns {url, final_url, status, headers, body(bytes), over_cap, error,
    redirects}; 4xx/5xx/3xx are responses (error=None) — only transport failures set
    error. An over-cap read is flagged via over_cap (body present but capped) so callers
    can treat it as an explicit error rather than silently mining partial bytes."""
    if max_bytes is None:
        max_bytes = MAX_BUNDLE_BYTES
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*",
               "Accept-Encoding": "identity", "Connection": "close", **(extra_headers or {})}
    hops: list[dict] = []
    cur = url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            req = urllib.request.Request(cur, headers=headers, method=method)
            try:
                with _OPENER.open(req, timeout=timeout) as resp:
                    body = resp.read(max_bytes + 1)
                    return {"url": url, "final_url": resp.geturl(), "status": resp.status,
                            "headers": _headers_to_dict(resp.headers),
                            "body": body[:max_bytes], "over_cap": len(body) > max_bytes,
                            "error": None, "redirects": hops}
            except urllib.error.HTTPError as e:  # 3xx (no-redirect opener), 4xx, 5xx
                loc = e.headers.get("Location") if e.headers else None
                if 300 <= e.code < 400 and loc and len(hops) < MAX_REDIRECTS:
                    hops.append({"status": e.code, "location": loc})
                    cur = urllib.parse.urljoin(cur, loc)
                    continue
                try:
                    raw = e.read(max_bytes + 1)
                    body, over = raw[:max_bytes], len(raw) > max_bytes
                except Exception:
                    body, over = b"", False
                return {"url": url, "final_url": cur, "status": e.code,
                        "headers": _headers_to_dict(e.headers), "body": body,
                        "over_cap": over, "error": None, "redirects": hops}
        return {"url": url, "final_url": cur, "status": None, "headers": {}, "body": None,
                "over_cap": False, "error": f"too many redirects (> {MAX_REDIRECTS})",
                "redirects": hops}
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as e:
        return {"url": url, "final_url": cur, "status": None, "headers": {}, "body": None,
                "over_cap": False, "error": f"{type(e).__name__}: {e}", "redirects": hops}


def _int_header(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _total_from_content_range(value) -> int | None:
    """'bytes 0-0/35500000' -> 35500000."""
    if not value or "/" not in value:
        return None
    return _int_header(value.rsplit("/", 1)[-1])


# --------------------------------------------------------------------------
# regex sets — EXACT patterns from js-analysis.md §2/§3 (grep -rhoiE equivalents:
# one alternation pass + re.IGNORECASE, like grep -i)
# --------------------------------------------------------------------------

# (kind, EXACT js-analysis.md §2 pattern, confidence tier, why-this-tier).
# Tier guidance is the doc's own: "pk_live/AIza (often restricted) = maybe low;
# sk_/private key/DB URI/session token = high". AWS access-key IDs (AKIA/ASIA) are
# identifiers — credential material, but only half a credential without the secret
# access key that may or may not sit elsewhere in the same bundle -> medium.
SECRET_PATTERNS = [
    ("aws_access_key_id", r"AKIA[A-Z0-9]{16}", "medium",
     "access key ID only — the paired secret access key is a separate string; verify the pair live"),
    ("aws_temp_access_key_id", r"ASIA[A-Z0-9]{16}", "medium",
     "temporary access key ID (STS) — short-lived; verify whether it is still valid"),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}", "low",
     "often restricted by referrer/API constraints (js-analysis.md §2)"),
    ("google_oauth_token", r"ya29\.[0-9A-Za-z_-]+", "low",
     "short-lived OAuth user token — usually expired by the time it ships in a bundle"),
    ("stripe_secret_key", r"sk_live_[0-9a-zA-Z]{24}", "high",
     "live Stripe secret key — full account control if valid"),
    ("stripe_restricted_key", r"rk_live_[0-9a-zA-Z]{24}", "high",
     "live Stripe restricted key — scoped but still a live credential"),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z-]+", "high",
     "Slack bearer token — workspace/API access if valid"),
    ("github_token", r"ghp_[0-9A-Za-z]{36}", "high",
     "GitHub personal access token — repo access if valid"),
    ("gitlab_token", r"glpat-[0-9A-Za-z_-]{20}", "high",
     "GitLab personal access token — repo access if valid"),
    ("jwt_shaped_token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "high",
     "JWT-shaped session token — decode and check alg/exp/claims"),
    ("pem_private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY", "high",
     "embedded private key header — extract the full key and check what it unlocks"),
    ("firebase_reference", r"firebase[A-Za-z]*", "low",
     "Firebase reference — project IDs are often public-by-design; check rules, not the ID"),
    ("mongodb_uri", r"mongodb(\+srv)?://", "high",
     "MongoDB connection URI — the scheme matched; read the context for host/credentials"),
    ("postgres_uri", r"postgres://", "high",
     "PostgreSQL connection URI — read the context for host/credentials"),
    ("mysql_uri", r"mysql://", "high",
     "MySQL connection URI — read the context for host/credentials"),
]
_SECRET_MASTER_RE = re.compile(
    "|".join("(?:%s)" % pat for _, pat, _, _ in SECRET_PATTERNS), re.IGNORECASE)
_SECRET_KIND_RES = [(kind, re.compile(pat, re.IGNORECASE))
                    for kind, pat, _, _ in SECRET_PATTERNS]

# Runtime-config vars (js-analysis.md §2, verbatim) — recon facts, not secrets: they
# carry the API base + client_id + key NAMES the agent needs. Reported in the
# js_endpoint_summary finding, never as js_secret findings.
RUNTIME_CONFIG_RE = re.compile(
    r"(REACT_APP_[A-Z_]+|VITE_[A-Z_]+|NG_[A-Z_]+|NEXT_PUBLIC_[A-Z_]+|__ENV__"
    r"|window\.__CONFIG__)[^,}]{0,90}", re.IGNORECASE)

# Endpoints/hosts/routes (js-analysis.md §3, verbatim).
HOST_RE = re.compile(r"https?://[a-z0-9.-]+\.[a-z]{2,}(:[0-9]+)?", re.IGNORECASE)
# NOTE: the doc's pattern anchors on a literal leading double-quote (JS string literal);
# kept verbatim on purpose so matches are JS string values, not prose mentions.
API_PATH_RE = re.compile(
    r"\"/(api|v[0-9]|rest|graphql|internal|admin|oauth|sso|auth|user|account)"
    r"[A-Za-z0-9/_.$%{}:-]{1,70}", re.IGNORECASE)
SPA_ROUTE_RE = re.compile(r"(path|route):\s*[\"']([/A-Za-z0-9:_-]{2,50})", re.IGNORECASE)


def _classify_secret(match_text: str) -> tuple[str, str] | None:
    for kind, rx in _SECRET_KIND_RES:
        if rx.fullmatch(match_text):
            tier = next(t for k, _, t, _ in SECRET_PATTERNS if k == kind)
            return kind, tier
    return None


def _context(text: str, start: int, end: int, width: int = 70) -> str:
    a, b = max(0, start - width), min(len(text), end + width)
    snippet = " ".join(text[a:b].split())
    return ("..." if a > 0 else "") + snippet + ("..." if b < len(text) else "")


def mine_text(text: str) -> dict:
    """Run the js-analysis.md §2/§3 extraction passes over one decoded bundle.
    Deterministic: hits in position order; endpoint/route lists sorted+deduped."""
    secrets, seen = [], set()
    for m in _SECRET_MASTER_RE.finditer(text):
        hit_text = m.group(0)
        classified = _classify_secret(hit_text)
        if classified is None:  # unreachable by construction; never guess a kind
            continue
        kind, tier = classified
        key = (kind, hit_text)
        if key in seen:
            continue
        seen.add(key)
        secrets.append({
            "kind": kind, "tier": tier, "match": hit_text,
            "line": text.count("\n", 0, m.start()) + 1,
            "context": _context(text, m.start(), m.end()),
        })
    hosts = sorted({m.group(0) for m in HOST_RE.finditer(text)})
    endpoints = sorted({m.group(0)[1:] for m in API_PATH_RE.finditer(text)})
    spa_routes = sorted({m.group(2) for m in SPA_ROUTE_RE.finditer(text)})
    runtime_config = sorted({m.group(0).strip() for m in RUNTIME_CONFIG_RE.finditer(text)})
    return {"secrets": secrets, "hosts": hosts, "endpoints": endpoints,
            "spa_routes": spa_routes, "runtime_config": runtime_config}


# --------------------------------------------------------------------------
# bundle download: probe (HEAD / 1-byte ranged GET) -> range-parallel or single-GET,
# size-asserted either way (js-analysis.md §1)
# --------------------------------------------------------------------------

def fetch_bundle(url: str, timeout: float, chunk_threshold_bytes: int, range_chunks: int,
                 ev) -> dict:
    """Download one bundle. Returns {url, status: ok|truncated|error, size,
    content_length, download, truncated, accept_ranges, data(bytes)|None, error}.
    On truncated/error, data is None — partial bytes are never mined."""
    out = {"url": url, "status": "error", "size": None, "content_length": None,
           "download": None, "truncated": False, "accept_ranges": None,
           "data": None, "error": None}

    # stage 1: declared size + range support. HEAD first; some CDNs reject HEAD but
    # honor Range, and a 206's Content-Range carries the total — that's the fallback.
    head = http_fetch(url, timeout, method="HEAD", max_bytes=1024)
    cl = ar = None
    if head["error"] is None and head["status"] is not None and head["status"] < 400:
        cl = _int_header(head["headers"].get("content-length"))
        ar = "bytes" in (head["headers"].get("accept-ranges") or "").lower()
        ev("HEAD -> HTTP %s, content-length: %s, accept-ranges: %s" % (
            head["status"], cl, head["headers"].get("accept-ranges") or "(absent)"))
    else:
        reason = head["error"] or ("HTTP %s" % head["status"])
        ev("HEAD probe unusable (%s) — falling back to a 1-byte ranged GET (bytes=0-0)" % reason)
        probe = http_fetch(url, timeout, extra_headers={"Range": "bytes=0-0"}, max_bytes=1024)
        if probe["error"] is None and probe["status"] == 206:
            cl = _total_from_content_range(probe["headers"].get("content-range"))
            ar = True
            ev("ranged probe -> 206, total from Content-Range: %s" % cl)
        elif probe["error"] is None and probe["status"] == 200:
            cl = _int_header(probe["headers"].get("content-length"))
            ar = False
            ev("ranged probe -> 200 (server ignores Range), content-length: %s" % cl)
        else:
            ev("ranged probe failed too — attempting one plain bounded GET")
    out["content_length"], out["accept_ranges"] = cl, ar

    if cl is not None and cl > MAX_BUNDLE_BYTES:
        out["error"] = ("declared size %dB exceeds the %dB safety cap — raise MAX_BUNDLE_BYTES "
                        "or fetch manually in chunks (js-analysis.md §1)" % (cl, MAX_BUNDLE_BYTES))
        return out

    if cl is not None and ar and cl >= chunk_threshold_bytes:
        return _download_ranges(url, timeout, cl, range_chunks, out, ev)
    return _download_single(url, timeout, cl, out, ev)


def _download_ranges(url: str, timeout: float, total: int, n_chunks: int,
                     out: dict, ev) -> dict:
    """Parallel byte-range pull (js-analysis.md §1's chunk loop, with retries and a
    hard assembled-size == Content-Length assertion)."""
    n = max(1, min(n_chunks, total))
    chunk_len = math.ceil(total / n)
    ranges = [(i * chunk_len, min((i + 1) * chunk_len, total) - 1) for i in range(n)]
    out["download"] = "range-parallel (%d chunks)" % n
    ev("size %dB >= threshold with Accept-Ranges: bytes — pulling %d parallel range "
       "chunks of ~%dB" % (total, n, chunk_len))

    def fetch_chunk(rng):
        s, e = rng
        expected = e - s + 1
        last_err = "untried"
        for _ in range(CHUNK_RETRIES + 1):
            r = http_fetch(url, timeout, extra_headers={"Range": "bytes=%d-%d" % (s, e)})
            if r["error"] is not None:
                last_err = r["error"]
                continue
            if r["over_cap"]:
                last_err = "chunk response over safety cap"
                continue
            if r["status"] == 206:
                body = r["body"] or b""
                if len(body) >= expected:
                    return body[:expected], None  # some servers over-deliver; spec says slice
                last_err = "206 body short: got %dB, expected %dB" % (len(body), expected)
                continue
            if r["status"] == 200:  # server ignored the Range header — slice the full body
                full = r["body"] or b""
                if len(full) >= e + 1:
                    return full[s:e + 1], None
                last_err = ("server ignored Range and its full body is only %dB "
                            "(< needed %dB)" % (len(full), e + 1))
                continue
            last_err = "HTTP %s" % r["status"]
        return None, last_err

    chunks: list = [None] * n
    failures: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures = {pool.submit(fetch_chunk, rng): i for i, rng in enumerate(ranges)}
        for fut in concurrent.futures.as_completed(futures):
            i = futures[fut]
            chunks[i], err = fut.result()
            if err is not None:
                failures[i] = (ranges[i], err)
    if failures:
        got = sum(len(c) for c in chunks if c is not None)
        detail = "; ".join("bytes %d-%d: %s" % (s, e, err)
                           for (s, e), err in (failures[i] for i in sorted(failures)))
        out.update(size=got, truncated=True, status="truncated",
                   error=("TRUNCATED_DOWNLOAD — range-parallel reassembly got %d of %d declared "
                          "bytes (%d/%d chunks ok, %d attempt(s) each); failures: %s. Bundle NOT "
                          "mined — a short pull is a false-negative factory (js-analysis.md §1); "
                          "retry, or fetch manually with curl --retry")
                         % (got, total, n - len(failures), n, CHUNK_RETRIES + 1, detail))
        return out
    data = b"".join(chunks)
    out["size"] = len(data)
    if len(data) != total:  # defensive: per-chunk length checks make this unreachable
        out.update(truncated=True, status="truncated",
                   error=("TRUNCATED_DOWNLOAD — assembled %dB != Content-Length %dB; bundle NOT "
                          "mined (js-analysis.md §1)") % (len(data), total))
        return out
    ev("reassembled %dB in chunk order == Content-Length %dB — asserted OK" % (len(data), total))
    out["status"], out["data"] = "ok", data
    return out


def _download_single(url: str, timeout: float, cl: int | None, out: dict, ev) -> dict:
    """One plain bounded GET — small bundles, or big ones whose origin announces no
    range support. Content-Length is still asserted whenever it is known (this is the
    exact single-stream silent-truncation failure from js-analysis.md §1)."""
    out["download"] = "single-GET"
    r = http_fetch(url, timeout)
    if r["error"] is not None:
        out["error"] = r["error"]
        return out
    if r["over_cap"]:
        out["error"] = ("body exceeds the %dB safety cap — raise MAX_BUNDLE_BYTES or fetch in "
                        "range chunks" % MAX_BUNDLE_BYTES)
        return out
    body = r["body"] or b""
    out["size"] = len(body)
    if cl is None:  # probe never produced a total; the GET's own header is the last chance
        cl = _int_header(r["headers"].get("content-length"))
        out["content_length"] = cl
    if cl is not None and len(body) != cl:
        out.update(truncated=True, status="truncated",
                   error=("TRUNCATED_DOWNLOAD — single-GET received %dB but Content-Length "
                          "declares %dB (the silently-truncated single-stream failure from "
                          "js-analysis.md §1). Bundle NOT mined; retry — if the origin announces "
                          "accept-ranges on a retry the range-parallel path will be used")
                         % (len(body), cl))
        return out
    ev("single-GET -> %dB%s" % (len(body), "" if cl is not None else
                                " (no Content-Length from server — assembled size could NOT be asserted)"))
    out["status"], out["data"] = "ok", body
    return out


# --------------------------------------------------------------------------
# source-map probe (js-analysis.md §3: "<url>.map — 200 = jackpot"; exposure is only
# claimed once the body parses as JSON source map — a 200 HTML error page is not one)
# --------------------------------------------------------------------------

def probe_sourcemap(js_url: str, timeout: float) -> dict:
    map_url = js_url + ".map"
    info = {"map_url": map_url, "probed": True, "exposed": False, "status": None,
            "sources": None, "sources_content": False, "note": None}
    r = http_fetch(map_url, timeout, max_bytes=MAX_SOURCEMAP_BYTES)
    if r["error"] is not None:
        info["note"] = "probe failed: %s" % r["error"]
        return info
    info["status"] = r["status"]
    if r["status"] != 200:
        return info  # 404 etc — the normal case, nothing to report
    if r["over_cap"]:
        info["note"] = ("HTTP 200 but body exceeds the %dB source-map cap — fetch manually to "
                        "confirm" % MAX_SOURCEMAP_BYTES)
        return info
    try:
        data = json.loads((r["body"] or b"").decode("utf-8", "replace"))
    except ValueError:
        info["note"] = ("HTTP 200 but body is not valid JSON (HTML error page or other) — "
                        "not a source map, not reported")
        return info
    if not isinstance(data, dict) or ("sources" not in data and "sourcesContent" not in data):
        info["note"] = ("HTTP 200 + valid JSON but no 'sources'/'sourcesContent' key — not a "
                        "source map, not reported")
        return info
    sources = data.get("sources")
    info["exposed"] = True
    info["sources"] = len(sources) if isinstance(sources, list) else None
    sc = data.get("sourcesContent")
    info["sources_content"] = isinstance(sc, list) and len(sc) > 0
    return info


# --------------------------------------------------------------------------
# findings (normalized contract — same shape as subdomain_takeover/cms_detect)
# --------------------------------------------------------------------------

TIER_SEVERITY = {"high": "medium", "medium": "low", "low": "info"}
TIER_CONFIDENCE = {"high": 0.70, "medium": 0.50, "low": 0.30}
TIER_RANK = {"high": 0, "medium": 1, "low": 2}

SECRET_NEXT_ACTION = ("regex pattern match only — never report on a match alone: verify the "
                      "credential live per validate.md (and check whether it is restricted or "
                      "public-by-design) before writing anything up")
SOURCEMAP_NEXT_ACTION = ("reconstruct with the .map's sourcesContent and grep for further "
                         "secrets/sinks manually (npx source-map-explorer, or jq -r "
                         "'.sourcesContent[]'); exposure itself is CWE-540 info disclosure — "
                         "deeper findings from the recovered source are out of scope for this "
                         "script and need manual review")
SUMMARY_NEXT_ACTION = ("feed discovered hosts/routes into authz + IDOR hunting "
                       "(framework-misconfig.md §7) and API proxy paths into the ssrf.md "
                       "candidate list; trace axios/fetch interceptors before declaring a "
                       "grepped route dead (js-analysis.md §3)")


def _secret_finding(hit: dict) -> dict:
    evidence = [
        "pattern class: %s (confidence tier: %s)" % (hit["kind"], hit["tier"]),
        "matched: %s" % hit["match"],
        "bundle: %s (line %d)" % (hit["bundle"], hit["line"]),
        "context: %s" % hit["context"],
        "regex pattern match only — NOT verified live; the matched value may be restricted, "
        "public-by-design, or a bundled example/placeholder",
    ]
    if hit.get("dup_bundles"):
        evidence.append("also seen in %d other bundle(s) in this run" % hit["dup_bundles"])
    tier_note = next(note for k, _, _, note in SECRET_PATTERNS if k == hit["kind"])
    evidence.append("tier rationale: %s" % tier_note)
    return {
        "type": "js_secret",
        "severity": TIER_SEVERITY[hit["tier"]],
        "confidence": TIER_CONFIDENCE[hit["tier"]],
        "target": hit["bundle"],
        "evidence": evidence,
        "source": SOURCE,
        "kind": hit["kind"],
        "line": hit["line"],
        "next_action": SECRET_NEXT_ACTION,
    }


def _sourcemap_finding(sm: dict, js_url: str) -> dict:
    evidence = [
        "%s -> HTTP 200" % sm["map_url"],
        "body confirmed parseable as a JSON source map (sources/sourcesContent present)",
        "source files referenced: %s" % (sm["sources"] if sm["sources"] is not None else "(sources key not a list)"),
        "sourcesContent present — original source recoverable" if sm["sources_content"]
        else "sourcesContent absent — source-file list only",
        "source-map exposure alone is a reportable info-disclosure (CWE-540), "
        "per js-analysis.md §3",
    ]
    return {
        "type": "js_sourcemap_exposure",
        "severity": "low",
        "confidence": 0.85,
        "target": js_url,
        "evidence": evidence,
        "source": SOURCE,
        "map_url": sm["map_url"],
        "next_action": SOURCEMAP_NEXT_ACTION,
    }


def _summary_finding(target: str, agg: dict, bundle_stats: list[dict]) -> dict:
    n_ok = sum(1 for b in bundle_stats if b["status"] == "ok")
    evidence = [
        "bundles processed: %d/%d ok (%d truncated, %d failed)" % (
            n_ok, len(bundle_stats),
            sum(1 for b in bundle_stats if b["status"] == "truncated"),
            sum(1 for b in bundle_stats if b["status"] == "error")),
        "backend hosts (%d): %s" % (len(agg["hosts"]), ", ".join(agg["hosts"]) or "(none)"),
        "API-shaped endpoints (%d): %s" % (len(agg["endpoints"]), ", ".join(agg["endpoints"]) or "(none)"),
        "SPA client-side routes (%d): %s" % (len(agg["spa_routes"]), ", ".join(agg["spa_routes"]) or "(none)"),
        "runtime-config vars (%d): %s" % (len(agg["runtime_config"]), ", ".join(agg["runtime_config"]) or "(none)"),
        "recon output, not a vulnerability — deduped across every bundle in this run",
    ]
    return {
        "type": "js_endpoint_summary",
        "severity": "info",
        "confidence": 0.90,
        "target": target,
        "evidence": evidence,
        "source": SOURCE,
        "hosts": list(agg["hosts"]),
        "endpoints": list(agg["endpoints"]),
        "spa_routes": list(agg["spa_routes"]),
        "runtime_config": list(agg["runtime_config"]),
        "next_action": SUMMARY_NEXT_ACTION,
    }


# --------------------------------------------------------------------------
# the pipeline
# --------------------------------------------------------------------------

def scan_urls(urls: list[str], timeout: float = DEFAULT_TIMEOUT,
              threads: int = DEFAULT_THREADS, range_chunks: int = DEFAULT_RANGE_CHUNKS,
              chunk_threshold_mb: float = DEFAULT_CHUNK_THRESHOLD_MB,
              verbose: bool = False) -> dict:
    """Full batch pipeline; returns ONE normalized result object for the whole batch
    (aggregated findings + per-bundle stats in metadata), whatever the batch size."""
    # dedupe, preserve order (recon/js.txt lists are anew'd but never trusted)
    seen: set = set()
    urls = [u for u in urls if not (u in seen or seen.add(u))]
    threshold_bytes = int(chunk_threshold_mb * 1024 * 1024)
    target_label = urls[0] if len(urls) == 1 else "batch:%d bundles" % len(urls)

    def run_one(url: str) -> dict:
        """One bundle: download -> mine -> sourcemap probe. Never raises: any unexpected
        error becomes that bundle's error entry (one bad bundle must not kill the run)."""
        local_ev: list[str] = []
        local_err: list[str] = []

        def ev(msg: str) -> None:
            local_ev.append("%s: %s" % (url, msg))
            if verbose:
                eprint("  [%s] %s" % (url, msg))

        record = {"url": url, "status": "error", "size": None, "content_length": None,
                  "download": None, "truncated": False, "accept_ranges": None,
                  "secrets": 0, "hosts": 0, "endpoints": 0, "spa_routes": 0,
                  "runtime_config": 0, "sourcemap": None, "error": None}
        mined = {"secrets": [], "hosts": [], "endpoints": [], "spa_routes": [],
                 "runtime_config": []}
        try:
            fetched = fetch_bundle(url, timeout, threshold_bytes, range_chunks, ev)
            record.update(status=fetched["status"], size=fetched["size"],
                          content_length=fetched["content_length"],
                          download=fetched["download"], truncated=fetched["truncated"],
                          accept_ranges=fetched["accept_ranges"], error=fetched["error"])
            if fetched["status"] == "truncated":
                local_err.append("%s: %s" % (url, fetched["error"]))
            elif fetched["status"] == "error":
                local_err.append("%s: FETCH_FAILED — %s" % (url, fetched["error"]))
            else:
                text = (fetched["data"] or b"").decode("utf-8", "replace")
                mined = mine_text(text)
                record.update(secrets=len(mined["secrets"]), hosts=len(mined["hosts"]),
                              endpoints=len(mined["endpoints"]),
                              spa_routes=len(mined["spa_routes"]),
                              runtime_config=len(mined["runtime_config"]))
                ev("mined: %d secret pattern(s), %d host(s), %d API endpoint(s), "
                   "%d SPA route(s), %d runtime-config var(s)"
                   % (record["secrets"], record["hosts"], record["endpoints"],
                      record["spa_routes"], record["runtime_config"]))

            if fetched["status"] == "error":
                # transport-level failure: the .map probe would just time out against a
                # dead host too — skip it and say so
                record["sourcemap"] = {"map_url": url + ".map", "probed": False,
                                       "exposed": False, "status": None, "sources": None,
                                       "sources_content": False,
                                       "note": "skipped — bundle fetch failed at transport level"}
            else:
                sm = probe_sourcemap(url, timeout)
                record["sourcemap"] = sm
                if sm["exposed"]:
                    ev("sourcemap %s: HTTP 200, parseable source map, %s source file(s)%s — "
                       "EXPOSED (CWE-540)" % (sm["map_url"], sm["sources"],
                                              ", sourcesContent present" if sm["sources_content"] else ""))
                elif sm["note"]:
                    ev("sourcemap %s: %s" % (sm["map_url"], sm["note"]))
                else:
                    ev("sourcemap %s: HTTP %s — not exposed" % (sm["map_url"], sm["status"]))
        except Exception as e:  # never let one bundle kill the run
            record["error"] = "unexpected error: %s: %s" % (type(e).__name__, e)
            local_err.append("%s: %s" % (url, record["error"]))
        return {"record": record, "mined": mined, "evidence": local_ev, "errors": local_err}

    if len(urls) == 1:
        results = [run_one(urls[0])]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, len(urls))) as pool:
            futures = {pool.submit(run_one, u): u for u in urls}
            by_url = {}
            for fut in concurrent.futures.as_completed(futures):
                by_url[futures[fut]] = fut.result()
            results = [by_url[u] for u in urls]  # preserve input order

    # ---- aggregate (deterministic: input order, then sorted within categories) ----
    evidence: list[str] = []
    errors: list[str] = []
    secrets_agg: dict = {}
    hosts, endpoints, spa_routes, runtime_config = set(), set(), set(), set()
    exposed_maps: list[tuple[str, dict]] = []
    for res in results:
        evidence.extend(res["evidence"])
        errors.extend(res["errors"])
        rec, mined = res["record"], res["mined"]
        for hit in mined["secrets"]:
            key = (hit["kind"], hit["match"])
            if key not in secrets_agg:
                secrets_agg[key] = {**hit, "bundle": rec["url"], "dup_bundles": 0}
            else:
                secrets_agg[key]["dup_bundles"] += 1
        hosts.update(mined["hosts"])
        endpoints.update(mined["endpoints"])
        spa_routes.update(mined["spa_routes"])
        runtime_config.update(mined["runtime_config"])
        if rec["sourcemap"] and rec["sourcemap"].get("exposed"):
            exposed_maps.append((rec["url"], rec["sourcemap"]))

    findings: list[dict] = []
    for hit in sorted(secrets_agg.values(),
                      key=lambda h: (TIER_RANK[h["tier"]], h["kind"], h["match"])):
        findings.append(_secret_finding(hit))
    for js_url, sm in exposed_maps:
        findings.append(_sourcemap_finding(sm, js_url))
    if any(r["record"]["status"] == "ok" for r in results):
        agg = {"hosts": sorted(hosts), "endpoints": sorted(endpoints),
               "spa_routes": sorted(spa_routes), "runtime_config": sorted(runtime_config)}
        findings.append(_summary_finding(target_label, agg, [r["record"] for r in results]))

    bundle_stats = [r["record"] for r in results]
    return {
        "tool": TOOL,
        "target": target_label,
        "timestamp": now_iso(),
        "status": "success",
        "findings": findings,
        "evidence": evidence,
        "errors": errors,
        "metadata": {
            "timeout_s": timeout,
            "threads": threads,
            "range_chunks": range_chunks,
            "chunk_threshold_bytes": threshold_bytes,
            "bundles": bundle_stats,
            "totals": {
                "secret_patterns": len(secrets_agg),
                "source_maps_exposed": len(exposed_maps),
                "hosts": len(hosts),
                "endpoints": len(endpoints),
                "spa_routes": len(spa_routes),
                "runtime_config_vars": len(runtime_config),
            },
        },
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


def print_human(result: dict, quiet: bool) -> None:
    if quiet:
        return
    for b in result["metadata"]["bundles"]:
        parts = [b["status"]]
        if b["size"] is not None:
            parts.append("%dB" % b["size"])
        if b["download"]:
            parts.append(b["download"])
        if b["truncated"]:
            parts.append("TRUNCATED — not mined")
        parts.append("secrets: %d, endpoints: %d, sourcemap: %s" % (
            b["secrets"], b["endpoints"],
            "EXPOSED" if (b["sourcemap"] or {}).get("exposed") else "no"))
        eprint("[%s] %s" % (b["url"], ", ".join(parts)))
    for err in result["errors"]:
        eprint("ERROR: %s" % err)
    totals = result["metadata"]["totals"]
    eprint("")
    eprint("totals: %d secret pattern(s), %d exposed source map(s), %d host(s), "
           "%d endpoint(s), %d SPA route(s)"
           % (totals["secret_patterns"], totals["source_maps_exposed"], totals["hosts"],
              totals["endpoints"], totals["spa_routes"]))
    eprint("")
    eprint("Next: verify any secret hit live per validate.md before reporting, reconstruct "
           "exposed .map files (jq -r '.sourcesContent[]') to mine the original source, and "
           "feed new hosts/routes into authz + IDOR hunting (framework-misconfig.md §7)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=SOURCE,
        description="JS bundle miner (js-analysis.md pipeline): range-parallel download with "
                    "hard size assertion, secret/key regex sweep, backend hosts + API paths + "
                    "SPA routes, and parse-confirmed .map exposure checks. Secrets are regex "
                    "matches only (severity capped at medium pending live validation); source-map "
                    "exposure is low/CWE-540; the aggregate summary is info.",
        epilog="examples:\n"
               "  %(prog)s https://host/app.min.js\n"
               "  %(prog)s -l recon/js.txt --json --output js_recon.json\n"
               "  %(prog)s -l recon/js.txt --range-chunks 16 --chunk-threshold-mb 5 --verbose\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("urls", nargs="*", metavar="url",
                    help="JS bundle URL(s) (full URLs, e.g. from recon/js.txt)")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file of JS URLs, one per line (# comments allowed) — recon/js.txt format")
    ap.add_argument("--json", action="store_true",
                    help="machine output on stdout (normalized JSON; ONE object for the whole batch)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SEC",
                    help="per-HTTP-operation timeout in seconds (default: 5)")
    ap.add_argument("--threads", type=int, default=DEFAULT_THREADS, metavar="N",
                    help="concurrent workers for the outer loop over bundles (default: 10)")
    ap.add_argument("--range-chunks", type=int, default=DEFAULT_RANGE_CHUNKS, metavar="N",
                    help="parallel byte-range chunks per large bundle (default: 12, "
                         "js-analysis.md §1 example)")
    ap.add_argument("--chunk-threshold-mb", type=float, default=DEFAULT_CHUNK_THRESHOLD_MB,
                    metavar="MB",
                    help="bundles at least this big with Accept-Ranges support use the "
                         "range-parallel path (default: 2)")
    ap.add_argument("--output", metavar="FILE",
                    help="also write the JSON result to this file")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress the human-readable summary (no effect with --json)")
    ap.add_argument("--verbose", action="store_true",
                    help="print each bundle's pipeline evidence to stderr as it runs")
    args = ap.parse_args(argv)

    urls: list[str] = list(args.urls)
    if args.list:
        try:
            urls.extend(load_target_list(args.list))
        except (OSError, FileNotFoundError) as e:
            eprint(f"[!] {e}")
            return 2
    urls = [u for u in (u.strip() for u in urls) if u]
    if not urls:
        ap.error("no JS URLs given (positional args or -l/--list FILE)")
    if args.timeout <= 0:
        ap.error("--timeout must be > 0")
    if args.threads < 1:
        ap.error("--threads must be >= 1")
    if args.range_chunks < 1:
        ap.error("--range-chunks must be >= 1")
    if args.chunk_threshold_mb < 0:
        ap.error("--chunk-threshold-mb must be >= 0")

    if not args.quiet and not args.json:
        eprint("[*] %s: %d bundle URL(s) | range-chunks: %d | chunk threshold: %sMB "
               "| timeout: %ss | pure stdlib HTTP" % (
                   TOOL, len(urls), args.range_chunks, args.chunk_threshold_mb, args.timeout))

    result = scan_urls(urls, timeout=args.timeout, threads=args.threads,
                       range_chunks=args.range_chunks,
                       chunk_threshold_mb=args.chunk_threshold_mb, verbose=args.verbose)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_human(result, quiet=args.quiet)

    if args.output:
        try:
            Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            if not args.quiet and not args.json:
                eprint("[*] JSON written to %s" % args.output)
        except OSError as e:
            eprint(f"[!] failed to write {args.output}: {e}")
            return 2

    return 0  # completed scan — exit non-zero only for hard errors above


if __name__ == "__main__":
    sys.exit(main())
