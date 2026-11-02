#!/usr/bin/env python3
"""cms_detect.py — adaptive CMS/technology fingerprinter (zero pip deps).

WHY: cms-wordpress-joomla.md and cms-moodle.md both open with "fingerprint first, then
route to the CMS-specific playbook" — but that step is done ad hoc today (one curl for a
generator tag, another for wp-json...). This script makes it one bounded, evidence-logging
call that an agent (or the recon agent) can run per host. It is deliberately ADAPTIVE: it
does not blind-sweep every CMS check against every target. The pipeline:

    TARGET -> HTTP DISCOVERY (one GET of /: https first, http fallback, redirects followed
              and logged, 64KB body cap, TLS verify off for intercepting proxies)
           -> CMS FINGERPRINT (weighted signals from scripts/data/cms_fingerprints.json:
              headers, <meta name=generator>, body regexes — scored WITHOUT extra requests;
              then path_exists probes for the TOP 1-2 candidates only)
           -> IF a CMS clears the confidence threshold (0.75):
                  VERSION (generator meta / header / discovery body first, then 1-2
                  version-disclosure paths — cached, never re-fetched)
                  + FOLLOW-UP (only the 1-3 CMS-specific requests worth making for THAT cms:
                  wp-json user enum, CVE-2023-23752 check, Moodle config dump, ...)
           -> IF no CMS clears threshold: generic tech fingerprint only (Server,
              X-Powered-By, concrete JS-framework markers) — never a fabricated CMS guess
           -> NORMALIZED RESULT (same JSON contract as subdomain_takeover.py)

Weighted-signal discipline (same as TASK-002: no single weak signal produces a verdict):
each signal carries a weight (definitive signals like a generator meta naming the CMS are
0.8-0.9; corroborating path probes 0.4-0.7; weak mentions 0.3-0.35). A CMS is "identified"
only when the SUM of matched weights >= CONFIDENCE_THRESHOLD (0.75) — i.e. one strong
definitive signal, or a weak mention corroborated by a second independent one. Scores for
all candidates land in metadata so the runner-up is visible, never hidden.

Severity discipline: detection itself is always "info" (fingerprinting is recon, not a
vuln). Only a follow-up check that surfaces something independently actionable (user
enumeration succeeding, an exposed CHANGELOG/version.php disclosing an exact version,
readable debug.log) gets its own "low" cms_exposure finding, with the exact reason in
evidence. By-design-public surfaces (Ghost /ghost/, Moodle's tool_mobile config dump) are
recorded as evidence facts, never escalated. Never auto-escalate the base finding.

Follow-up checks are read-only GETs/POSTs against documented recon endpoints (no login
attempts, no brute force, no payload injection) — same scope discipline as every script
in this repo: run against in-scope targets only.

DB schema (scripts/data/cms_fingerprints.json): array of
  {cms, confidence_basis: "well-documented"|"community-report", doc,
   confidence_signals: [{type: header|body_regex|path_exists|meta_generator,
                         detail, match, weight}],
   version_signals: [{source: meta_generator|header|body|path, regex, note,
                      header? (for source=header), path? (for source=path)}],
   follow_up: [{path, purpose, method: GET|POST, body? (POST payload),
                expose_when?: {status: [codes], body_regex}, exposure?}]}
Every regex in the DB is validated by tests/test_cms_detect.py.

Zero pip dependencies by design — `pip install` routinely fails under PEP-668 on sandboxed
engagement boxes (house precedent: scripts/favicon_hash.py, scripts/subdomain_takeover.py).
Pure stdlib HTTP probing — no external binary, no find_tool() seam (deliberately: nothing
here shells out). Python 3.8+ (3.11-era `X | Y` annotations are strings via __future__).

Usage:
    python3 cms_detect.py https://target.example [more ...]      # bare hosts ok too
    python3 cms_detect.py -l recon/hosts.txt --json --output cms.json
    python3 cms_detect.py target.example --verbose               # stage-by-stage to stderr

Exit code: 0 for a completed scan (identified, not identified, or unreachable),
non-zero only for hard errors (bad args, missing -l file, unreadable fingerprint DB).
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

TOOL = "cms_detect"
SCRIPT_DIR = Path(__file__).resolve().parent
FINGERPRINTS_FILE = SCRIPT_DIR / "data" / "cms_fingerprints.json"
SOURCE = "cms_detect.py"

MAX_BODY_BYTES = 64 * 1024   # fingerprint pages are tiny; never buffer a whole site
MAX_REDIRECTS = 4            # logged hop by hop, then stop
CONFIDENCE_THRESHOLD = 0.75  # summed signal weights needed to call a CMS identified
MAX_PATH_PROBE_CANDIDATES = 2  # path_exists probes only for the top-N header/body candidates
CONFIDENCE_CAP = 0.95        # never claim certainty from HTTP fingerprints alone
USER_AGENT = "Mozilla/5.0 (compatible; moraa-cmsdetect/1.0; authorized-scope-use-only)"

# Concrete JS-framework/site-builder markers for the generic (no-CMS) fingerprint. Every
# marker is a literal DOM/URL artifact — nothing speculative ("React detected" from nothing
# is exactly what this list must never do). Only observed matches are ever reported.
TECH_MARKERS = [
    ("Next.js", "__NEXT_DATA__"),
    ("Next.js", "/_next/static/"),
    ("Nuxt", "__NUXT__"),
    ("SvelteKit", "data-sveltekit-"),
    ("Angular", "ng-version="),
    ("Vue 3", "data-v-app"),
    ("React (legacy SSR)", "data-reactroot"),
    ("Gatsby", "___gatsby"),
    ("Astro", "astro-island"),
    ("Shopify", "cdn.shopify.com"),
    ("Wix", "wixstatic"),
    ("Squarespace", "squarespace.com/static"),
    ("Webflow", "assets.website-files.com"),
]

META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
META_NAME_RE = re.compile(r"name\s*=\s*[\"']generator[\"']", re.IGNORECASE)
META_CONTENT_RE = re.compile(r"content\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# HTTP probe (stdlib urllib — no requests; adapted from subdomain_takeover.probe_http:
# same bounded GET, 64KB cap, TLS-verify-off, 4xx/5xx-are-responses semantics, but with
# explicit capped redirect-following so a http->https or apex->www 301 doesn't leave us
# fingerprinting an empty redirect body; every hop is logged)
# --------------------------------------------------------------------------

def _build_opener() -> urllib.request.OpenerDirector:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # engagement boxes run intercepting proxies (favicon_hash.py precedent)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # we follow redirects ourselves, hop by hop, and log each one

    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))


_OPENER = _build_opener()


def _headers_to_dict(hdrs) -> dict:
    """Lower-cased header dict; multiple Set-Cookie lines joined with '; ' so cookie-name
    signals (MoodleSession) can be matched against a single string."""
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
# fingerprint DB
# --------------------------------------------------------------------------

def load_fingerprints(path: Path = FINGERPRINTS_FILE) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array of CMS fingerprint objects")
    return data


def extract_generators(body: str) -> list[str]:
    """All <meta name='generator' content='...'> contents (attribute order agnostic)."""
    out: list[str] = []
    for tag in META_TAG_RE.findall(body):
        if META_NAME_RE.search(tag):
            m = META_CONTENT_RE.search(tag)
            if m:
                out.append(m.group(1))
    return out


def _signal_matched(sig: dict, headers: dict, generators: list[str], body: str,
                    path_status: int | None) -> bool:
    t = sig.get("type")
    match = sig.get("match", "")
    if t == "header":
        return match.lower() in headers.get(_header_key(sig), "")
    if t == "meta_generator":
        return any(match.lower() in g.lower() for g in generators)
    if t == "body_regex":
        try:
            return re.search(match, body, re.IGNORECASE) is not None
        except re.error:
            return False  # a broken DB pattern must never take the scanner down
    if t == "path_exists":
        return path_status is not None and path_status < 400
    return False


def _header_key(sig: dict) -> str:
    """Header signals store the header name in `detail`; recover a header dict key from it
    (e.g. 'Set-Cookie' / 'X-Generator' / 'X-Powered-By header' -> lowercase dict key)."""
    d = sig.get("detail", "")
    d = re.sub(r"\s*\([^)]*\)\s*$", "", d)      # strip trailing "(D8+)" style annotations
    d = re.sub(r"\s+header$", "", d, flags=re.I)
    return d.strip().lower()


def score_signals(cms_entry: dict, headers: dict, generators: list[str], body: str,
                  path_statuses: dict) -> tuple[float, list[str]]:
    """Sum weights of matched confidence_signals; return (score, matched-signal notes)."""
    score, matched = 0.0, []
    for sig in cms_entry.get("confidence_signals", []):
        path_status = path_statuses.get(sig.get("match"))
        if _signal_matched(sig, headers, generators, body, path_status):
            w = float(sig.get("weight", 0.0))
            score += w
            matched.append(f"{cms_entry['cms']} {sig.get('type')} \"{sig.get('detail')}\" (+{w:.2f})")
    return score, matched


# --------------------------------------------------------------------------
# version extraction / follow-up fact extraction
# --------------------------------------------------------------------------

def extract_version(entry: dict, headers: dict, generators: list[str], body: str,
                    fetch) -> dict | None:
    """Run version_signals in order: no-request sources first (generator/header/body),
    then version paths. First hit wins. `fetch(path)` -> probe dict (cached)."""
    for vs in entry.get("version_signals", []):
        src = vs.get("source")
        try:
            if src == "meta_generator":
                hay = "; ".join(generators)
            elif src == "header":
                hay = headers.get(vs.get("header", "").lower(), "")
            elif src == "body":
                hay = body
            elif src == "path":
                r = fetch(vs.get("path", ""))
                if r["error"] is not None or r["status"] != 200:
                    continue
                hay = r["body"] or ""
            else:
                continue
            m = re.search(vs.get("regex", ""), hay)
            if m:
                via = {"meta_generator": "generator meta tag", "header": f"{vs.get('header')} header",
                       "body": "discovery body", "path": f"{vs.get('path')}"}[src]
                note = f" ({vs['note']})" if vs.get("note") else ""
                return {"value": m.group(1).strip(), "via": via + note}
        except re.error:
            continue
    return None


def _extract_fact(cms: str, path: str, probe: dict) -> str | None:
    """CMS-specific fact extraction for a follow-up response: a specific extracted fact
    (usernames, registerauth, ...) — never a raw body dump. None -> generic excerpt."""
    body = probe.get("body") or ""
    if cms == "WordPress" and path == "/wp-json/wp/v2/users":
        try:
            users = json.loads(body)
            slugs = [u.get("slug", u.get("name", f"id:{u.get('id')}")) for u in users
                     if isinstance(u, dict)]
            if slugs:
                return f"usernames: {', '.join(str(s) for s in slugs[:10])} ({len(slugs)} user(s))"
            return "empty user list (enumeration blocked or no users exposed)"
        except (ValueError, AttributeError):
            return None
    if cms == "Moodle" and path.startswith("/lib/ajax/service-nologin.php"):
        try:
            data = json.loads(body)
            cfg = data[0].get("data") if isinstance(data, list) and data else None
            if isinstance(cfg, dict):
                facts = []
                if "registerauth" in cfg:
                    ra = cfg.get("registerauth")
                    facts.append("registerauth=" + (ra if ra else "(empty — self-registration closed)"))
                for k in ("guestlogin", "enablewebservices"):
                    if k in cfg:
                        facts.append(f"{k}={cfg[k]}")
                idps = cfg.get("identityproviders") or []
                if idps:
                    names = [i.get("name", "?") if isinstance(i, dict) else str(i) for i in idps]
                    facts.append(f"identityproviders={len(idps)}: {', '.join(names[:5])}")
                return "; ".join(facts) or "config returned (no notable fields)"
        except (ValueError, AttributeError, IndexError):
            return None
    return None


def _excerpt(body: str | None, limit: int = 160) -> str:
    if not body:
        return ""
    flat = " ".join(body.split())
    return flat[:limit] + ("..." if len(flat) > limit else "")


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


def scan_target(target: str, fingerprints: list[dict], timeout: float = 5.0,
                verbose: bool = False) -> dict:
    """Full adaptive pipeline for one target; returns the normalized result object."""
    evidence: list[str] = []
    errors: list[str] = []
    requests_made: list[str] = []
    cache: dict = {}

    def ev(msg: str) -> None:
        evidence.append(msg)
        if verbose:
            eprint(f"  [{target}] {msg}")

    def fetch(path: str, data: bytes | None = None) -> dict:
        """Cached bounded GET/POST against the discovery base — path probes, version
        paths and follow-ups all share one cache so nothing is ever fetched twice."""
        key = ("POST" if data is not None else "GET", path)
        if key not in cache:
            url = path if "://" in path else base_url.rstrip("/") + path
            parts = urllib.parse.urlsplit(url)
            r = probe_http(url, timeout, data=data)
            cache[key] = r
            requests_made.append(("POST " if data is not None else "GET ") + parts.path
                                 + (("?" + parts.query) if parts.query else ""))
        return cache[key]

    # ---- stage 1: HTTP discovery --------------------------------------------
    base_url, discovery = None, None
    for candidate in normalize_target(target):
        r = probe_http(candidate, timeout)
        requests_made.append("GET " + candidate)
        if r["error"] is None:
            base_url, discovery = candidate, r
            if r["redirects"]:
                chain = " -> ".join(f"{h['status']} {h['location']}" for h in r["redirects"])
                ev(f"discovery: {candidate} redirected: {chain}")
            ev(f"discovery: {r['final_url']} -> HTTP {r['status']} ({len(r['body'] or '')}B body)")
            break
        errors.append(f"{candidate}: {r['error']}")
        ev(f"discovery: {candidate} failed ({r['error']})")

    headers = (discovery or {}).get("headers", {})
    body = (discovery or {}).get("body") or ""
    generators = extract_generators(body)

    # generic tech signals — always collected, primary evidence when no CMS is identified
    generic = {"server": headers.get("server"), "x_powered_by": headers.get("x-powered-by"),
               "markers": [{"tech": t, "evidence": m} for t, m in TECH_MARKERS
                           if m.lower() in body.lower()]}
    if generic["server"]:
        ev(f"tech: Server: {generic['server']}")
    if generic["x_powered_by"]:
        ev(f"tech: X-Powered-By: {generic['x_powered_by']}")
    for m in generic["markers"]:
        ev(f"tech: {m['tech']} marker \"{m['evidence']}\"")

    def finish(cms: str | None, score: float, scores_meta: list[dict],
               version: dict | None, exposures: list[dict], next_action: str) -> dict:
        conf = min(CONFIDENCE_CAP, round(score, 2)) if cms else 0.5
        finding = {
            "type": "cms_detection", "severity": "info", "confidence": conf,
            "target": target, "evidence": list(evidence), "source": SOURCE,
            "cms": cms,
            "version": (version or {}).get("value"),
            "next_action": next_action,
        }
        findings = [finding] + exposures
        return {
            "tool": TOOL, "target": target, "timestamp": now_iso(), "status": "success",
            "findings": findings, "evidence": list(evidence), "errors": list(errors),
            "metadata": {
                "timeout_s": timeout, "threshold": CONFIDENCE_THRESHOLD,
                "requests_made": requests_made,
                "cms_scores": scores_meta,
                "version": version,
                "generic_tech": generic,
                "fingerprint_db": {"file": "scripts/data/cms_fingerprints.json",
                                   "entries": len(fingerprints)},
            },
        }

    # ---- unreachable target: evidence + errors, never a crash ----------------
    if discovery is None:
        ev("discovery: no HTTP response from any scheme — target unreachable")
        return finish(None, 0.0, [], None, [],
                      "target unreachable — confirm the host is live and in-scope before re-testing")

    if not fingerprints:
        errors.append("fingerprint DB empty — CMS identification skipped")
        ev("fingerprint: DB empty — generic tech fingerprint only")

    # ---- stage 2: header/meta/body scoring (zero extra requests) -------------
    path_statuses: dict = {}
    candidates: list[tuple[dict, float, list[str]]] = []
    for entry in fingerprints:
        score, matched = score_signals(entry, headers, generators, body, path_statuses)
        candidates.append((entry, score, matched))
    candidates.sort(key=lambda c: -c[1])

    # ---- stage 2b: path_exists probes for the top 1-2 candidates only -------
    probed = [c for c in candidates if c[1] > 0][:MAX_PATH_PROBE_CANDIDATES]
    rescored: list[tuple[dict, float, list[str]]] = []
    for entry, score, matched in candidates:
        if entry in [p[0] for p in probed]:
            paths = [s["match"] for s in entry.get("confidence_signals", [])
                     if s.get("type") == "path_exists"]
            for p in paths:
                r = fetch(p)
                status = None if r["error"] is not None else r["status"]
                path_statuses[p] = status
                label = "match" if (status is not None and status < 400) else f"HTTP {status}"
                ev(f"path probe [{entry['cms']}]: {p} -> {label}")
            score, matched = score_signals(entry, headers, generators, body, path_statuses)
        rescored.append((entry, score, matched))
    rescored.sort(key=lambda c: (-c[1],))  # stable: DB order breaks ties deterministically

    scores_meta = [{"cms": e["cms"], "score": round(s, 2)} for e, s, _ in rescored]

    # ---- verdict -------------------------------------------------------------
    winner, wscore, wmatched = rescored[0] if rescored else (None, 0.0, [])
    runner_up = rescored[1] if len(rescored) > 1 else None
    for m in wmatched:
        ev(f"signal: {m}")
    if winner is None:
        return finish(None, 0.0, scores_meta, None, [], "no CMS identified")

    cms = winner["cms"]
    if wscore < CONFIDENCE_THRESHOLD:
        ru = f", runner-up {runner_up[0]['cms']} at {runner_up[1]:.2f}" if runner_up else ""
        ev(f"verdict: best candidate {cms} scored {wscore:.2f} < threshold "
           f"{CONFIDENCE_THRESHOLD}{ru} — not identified")
        return finish(None, 0.0, scores_meta, None, [],
                      "no CMS identified, generic tech fingerprint only — fingerprint DB "
                      "coverage is finite; verify manually (wappalyzer/whatweb) if CMS "
                      "presence is suspected")

    basis = winner.get("confidence_basis", "unknown")
    ru = f"; runner-up: {runner_up[0]['cms']} {runner_up[1]:.2f}" if runner_up else ""
    ev(f"verdict: {cms} identified — score {wscore:.2f} >= threshold {CONFIDENCE_THRESHOLD} "
       f"({basis}){ru}")

    # ---- stage 3: version extraction (identified CMS only) -------------------
    version = extract_version(winner, headers, generators, body, fetch)
    if version:
        ev(f"version: {version['value']} via {version['via']}")
    else:
        ev("version: not disclosed by any version signal")

    # ---- stage 4: CMS-specific follow-ups (identified CMS only) --------------
    exposures: list[dict] = []
    for fu in winner.get("follow_up", []):
        path, purpose = fu.get("path"), fu.get("purpose", "")
        data = fu.get("body").encode("utf-8") if fu.get("body") else None
        r = fetch(path, data=data)
        if r["error"] is not None:
            ev(f"follow-up: {path} failed ({r['error']})")
            continue
        fact = _extract_fact(cms, path, r)
        detail = fact or _excerpt(r.get("body"))
        ev(f"follow-up: {path} -> HTTP {r['status']}"
           + (f" — {detail}" if detail else f" — {purpose}"))
        ew = fu.get("expose_when")
        if ew and r["status"] in ew.get("status", []) and ew.get("body_regex"):
            try:
                hit = re.search(ew["body_regex"], r.get("body") or "", re.IGNORECASE)
            except re.error:
                hit = None
            if hit:
                exposure = fu.get("exposure", purpose)
                ev(f"exposure: {exposure}")
                exposures.append({
                    "type": "cms_exposure", "severity": "low", "confidence": 0.8,
                    "target": target, "source": SOURCE, "cms": cms,
                    "evidence": [f"{path} -> HTTP {r['status']}",
                                 detail or _excerpt(r.get("body")), exposure],
                    "next_action": exposure + " — confirm manually before reporting",
                })

    # ---- normalized result ----------------------------------------------------
    doc = winner.get("doc")
    if exposures:
        next_action = exposures[0]["next_action"]
    elif doc:
        next_action = (f"{cms}" + (f" {version['value']}" if version else "")
                       + f" identified — enumerate plugins/themes/components and map versions"
                         f" to known issues (see {doc})")
    else:
        next_action = (f"{cms}" + (f" {version['value']}" if version else "")
                       + " identified — map version to known issues manually")
    return finish(cms, wscore, scores_meta, version, exposures, next_action)


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
    interesting = []
    for r in results:
        if r["findings"]:
            f = r["findings"][0]
            cms = f.get("cms")
            ver = f.get("version")
            line = f"{cms or 'no CMS identified'}" + (f" {ver}" if ver else "")
            eprint(f"[{r['target']}] {line}")
            if f.get("cms"):
                interesting.append(f)
        for err in r["errors"]:
            eprint(f"[{r['target']}] ERROR: {err}")
    if interesting:
        eprint("")
        for f in interesting:
            eprint(f"  -> [{f['target']}] {f['next_action']}")
    eprint("")
    eprint("Next: route identified CMSs through their playbook (cms-wordpress-joomla.md / "
           "cms-moodle.md), re-run interesting targets with --verbose for stage-by-stage "
           "evidence, and confirm every exposure manually before reporting")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=SOURCE,
        description="Adaptive CMS/web-technology fingerprinter — weighted-signal CMS "
                    "identification, version extraction, and CMS-specific follow-up checks "
                    "(detection is recon/info; exposures get their own low finding).",
        epilog="examples:\n"
               "  %(prog)s https://target.example\n"
               "  %(prog)s -l recon/hosts.txt --json --output cms.json --threads 20\n"
               "  %(prog)s target.example --verbose   # stage-by-stage evidence to stderr\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", metavar="target",
                    help="target URL(s) or bare host(s) (bare hosts try https then http)")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file of targets, one per line (# comments allowed)")
    ap.add_argument("--json", action="store_true",
                    help="machine output on stdout (normalized JSON; array when >1 target)")
    ap.add_argument("--timeout", type=float, default=5.0, metavar="SEC",
                    help="per-HTTP-operation timeout in seconds (default: 5)")
    ap.add_argument("--threads", type=int, default=10, metavar="N",
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

    try:
        fingerprints = load_fingerprints()
    except (OSError, ValueError) as e:
        eprint(f"[!] cannot load fingerprint DB {FINGERPRINTS_FILE}: {e}")
        return 2

    if not args.quiet and not args.json:
        eprint(f"[*] {TOOL}: {len(targets)} target(s) | fingerprints: {len(fingerprints)} CMSs "
               f"| threshold: {CONFIDENCE_THRESHOLD} | timeout: {args.timeout}s | pure stdlib HTTP")

    def run_one(t: str) -> dict:
        try:
            return scan_target(t, fingerprints, timeout=args.timeout, verbose=args.verbose)
        except Exception as e:  # never let one target kill the run
            return {"tool": TOOL, "target": t, "timestamp": now_iso(), "status": "success",
                    "findings": [], "evidence": [], 
                    "errors": [f"unexpected error: {type(e).__name__}: {e}"],
                    "metadata": {"timeout_s": args.timeout, "threshold": CONFIDENCE_THRESHOLD}}

    if len(targets) == 1:
        results = [run_one(targets[0])]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, len(targets))) as ex:
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
            Path(args.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            if not args.quiet and not args.json:
                eprint(f"[*] JSON written to {args.output}")
        except OSError as e:
            eprint(f"[!] failed to write {args.output}: {e}")
            return 2

    return 0  # completed scan — exit non-zero only for hard errors above


if __name__ == "__main__":
    sys.exit(main())
