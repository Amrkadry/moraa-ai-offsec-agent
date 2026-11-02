#!/usr/bin/env python3
"""github_recon.py — GitHub/code-recon ORCHESTRATOR (recon.md §4), not a secret-scanning
reimplementation.

WHY: trufflehog and gitleaks already do secret detection extremely well; rewriting a
third regex engine would be worse at it and would drift. This script's job is to
(1) detect whether the real tools are installed (find_tool(), a Python mirror of
    scripts/lib/tools.sh, same pattern as subdomain_takeover.find_tool()),
(2) run them with their confirmed CLI syntax when present,
(3) run recon.md §4's GitHub-code-search dork sweep directly against the REST API,
(4) normalize whatever combination of sources ACTUALLY RAN into this repo's JSON
    contract — with sources_skipped[] carrying a reason for every source that did not
    run, so an agent reading the output can never mistake "nothing found because
    trufflehog isn't installed" for "trufflehog ran and found nothing".

Wrapped tools — confirmed real CLI syntax (installed under ~/go/bin in this environment):

    trufflehog github --org=<ORG> --json --token=<TOKEN> --results=verified,unverified
        Verification is ON (no --no-verification): trufflehog's live provider-API
        check is the whole point of it over a bare regex sweep, and a VERIFIED hit is
        the one place an automated "high" severity is genuinely justified in this repo.
        Output is JSONL (one JSON object per line on stdout) — parsed line by line.
        Org-wide via --org=<ORG>; explicit repos would need repeated --repo=<o/n>,
        which this script does not construct (use --local-repo + gitleaks instead).
        Runs only when: installed AND --org given AND a GH_TOKEN is available.

    gitleaks detect --no-git -s <cloned-repo-dir> --report-format json --report-path <file>
        SCOPE BOUNDARY: gitleaks scans a LOCAL directory only — it cannot take a GitHub
        org/user, and this script will NOT clone org repos to feed it (cloning arbitrary
        org repos is a much bigger, riskier action than a read-only API call — a human
        decides what gets cloned). So gitleaks here is opt-in via --local-repo <path>
        for a repo the user has ALREADY cloned; without that argument gitleaks is
        recorded in sources_skipped with exactly that reason. gitleaks exits rc=1 when
        leaks are found — that is expected output, not a failure. gitleaks needs no token.
        Its hits are regex matches (NOT live-verified) -> medium, same as an unverified
        trufflehog hit.

    github-subdomains -d <DOMAIN> -t <TOKEN> -raw
        Subdomains of DOMAIN mentioned in GitHub code. Line-per-subdomain stdout is
        parsed into metadata.subdomains_found + ONE info-severity summary finding
        (recon output like js_recon.py's endpoint summary — not a vulnerability).
        Runs only when: installed AND --domain given AND a GH_TOKEN is available.

    GitHub REST code-search dork sweep: GET https://api.github.com/search/code?q=<dork>
        with Authorization: Bearer <token>, Accept: application/vnd.github+json,
        X-GitHub-Api-Version: 2022-11-28. recon.md §4's dork list, adapted from the
        doc's TARGETORG/TARGET.com placeholders to --org/--domain. Unauthenticated code
        search returns ZERO results (confirmed in this repo's own history — recon.md
        §4), so the whole sweep needs a token; without one it is skipped, not faked.
        Code search is rate-limited to 10 req/min even authenticated: queries run
        sequentially with a small sleep between them (DORK_QUERY_SLEEP_S=3s; this is a
        handful of high-signal dorks, not a bulk scan), and a 403/422 response is
        recorded as a rate-limited/skipped dork in evidence+metadata — no retries, no
        hammering, the sweep continues with the next dork. Hits are recorded as
        repo/path/name only — the file CONTENT is never fetched automatically (opening
        a promising hit is a deliberate human next step, stated in next_action).

Token convention (mirrors lib/config.sh moraa_config_get, env-first precedence):
    1. --token <token> CLI argument
    2. GH_TOKEN environment variable
    3. "GH_TOKEN" key in ~/.moraa/config.json (MORAA_CONFIG_FILE overrides the path,
       same as the bash helper)
    The token value is never printed; only its SOURCE is recorded in metadata.

No secrets in evidence (findings discipline, same as exposure_sweep.redact_remote()):
trufflehog's "Raw" value and gitleaks' "Secret" value are parsed ONLY to be scrubbed —
findings carry detector name / rule id, repo, file, line, commit and the Verified bool.
A make_scrubber()-based safety net re-scrubs every evidence/error string against every
collected raw value AND the token itself, so a tool echoing its own argv into stderr
cannot leak the secret into the report either.

Severity contract (output_contract): trufflehog VERIFIED -> high (verified live against
the actual provider API by the tool — real evidence, not regex); unverified
trufflehog / any gitleaks hit -> medium ("detector matched, NOT live-verified — confirm
before reporting"); a dork hit -> low (this script cannot assess file content, only that
a dork matched — manually open the file); github-subdomains -> one info summary finding.

Timeouts: --timeout (default 10s) applies to each GitHub REST API call — GitHub API is
slower than the siblings' local probes. Wrapped tools get TOOL_TIMEOUT_S (900s): an
org-wide trufflehog run is legitimately many minutes, and a 10s cap would guarantee
false "tool failed" results. Both are recorded in metadata.

Exit code: 0 for a completed scan — even when EVERY source was skipped for lack of
tools/token (that is a valid, reportable outcome, not an error). Non-zero (2) only for
hard argument errors: neither --org nor --domain given, --timeout <= 0, or a
--local-repo path that does not exist.

Usage:
    python3 github_recon.py --org targetorg
    python3 github_recon.py --org targetorg --domain target.com --json --output gh.json
    python3 github_recon.py --domain target.com --local-repo ~/clones/target-api
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

TOOL = "github_recon"
SOURCE = "github_recon.py"

USER_AGENT = "Mozilla/5.0 (compatible; moraa-githubrecon/1.0; authorized-scope-use-only)"

GITHUB_API = "https://api.github.com"
SEARCH_ENDPOINT = GITHUB_API + "/search/code"
API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": USER_AGENT,
}
MAX_API_RESPONSE_BYTES = 4 * 1024 * 1024   # search responses are KBs; runaway guard only
PER_PAGE = 50                              # bounded first page; pagination is a deliberate
                                           # human step (noted in evidence when truncated)

DEFAULT_TIMEOUT = 10.0   # per GitHub-API-call timeout (slower than the siblings' local probes)
TOOL_TIMEOUT_S = 900.0   # per wrapped-tool invocation (org-wide trufflehog is many minutes)
DORK_QUERY_SLEEP_S = 3.0 # between code-search calls: 10 req/min limit, ~20 req/3min worst case
MAX_HITS_EVIDENCE = 10   # dork hits SHOWN in evidence; all returned items kept in the finding

# Mirrors scripts/lib/tools.sh's extra search dirs so bash and python tooling find the
# same binaries (a non-login shell often lacks ~/go/bin on PATH).
EXTRA_TOOL_DIRS = (
    "~/go/bin",
    "~/.local/go/bin",
    "~/.local/bin",
    "/usr/local/bin",
    "/usr/local/sbin",
)

HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# tool discovery (python mirror of lib/tools.sh / subdomain_takeover.find_tool)
# --------------------------------------------------------------------------

def find_tool(name: str) -> str | None:
    """PATH first (shutil.which), then the same extra dirs lib/tools.sh checks, then /opt/*/bin."""
    p = shutil.which(name)
    if p:
        return p
    for d in EXTRA_TOOL_DIRS:
        cand = Path(d).expanduser() / name
        if cand.is_file() and cand.stat().st_mode & 0o111:
            return str(cand)
    for d in sorted(glob.glob("/opt/*/bin")):
        cand = Path(d) / name
        if cand.is_file() and cand.stat().st_mode & 0o111:
            return str(cand)
    return None


# --------------------------------------------------------------------------
# token lookup (python mirror of lib/config.sh moraa_config_get: env first, then
# ~/.moraa/config.json; MORAA_CONFIG_FILE overrides the path exactly like the bash
# helper). Values are never printed — only which source supplied them.
# --------------------------------------------------------------------------

def _config_json_get(path: str, key: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    val = data.get(key) if isinstance(data, dict) else None
    return str(val) if val else None


def get_github_token(cli_token: str | None = None) -> tuple[str | None, str | None]:
    """-> (token, source) where source is 'cli' | 'env' | 'config-file' | None."""
    if cli_token:
        return cli_token, "cli"
    env = os.environ.get("GH_TOKEN", "").strip()
    if env:
        return env, "env"
    cfg_path = os.environ.get("MORAA_CONFIG_FILE") or str(
        Path.home() / ".moraa" / "config.json")
    val = _config_json_get(cfg_path, "GH_TOKEN")
    if val:
        return val, "config-file"
    return None, None


# --------------------------------------------------------------------------
# redaction safety net (exposure_sweep.redact_remote() precedent, applied to
# trufflehog's Raw / gitleaks' Secret / the token itself)
# --------------------------------------------------------------------------

def make_scrubber(*secrets: str):
    """Return fn(text)->text replacing every collected secret value with a redaction
    marker. Applied to EVERY evidence/error string before it enters the result — the
    primary defense is simply never copying Raw/Secret into output; this catches the
    indirect path (a tool echoing its own --token argv into a crash message)."""
    known = [s for s in secrets if s]

    def scrub(text: str) -> str:
        for s in known:
            if s in text:
                text = text.replace(s, "<redacted:%d-chars>" % len(s))
        return text

    return scrub


# --------------------------------------------------------------------------
# the two external seams: subprocess for wrapped tools, urllib for the GitHub API
# --------------------------------------------------------------------------

def run_tool(argv: list[str], timeout: float):
    """One wrapped-tool invocation. Argument LIST only — never shell=True, never
    interpolated strings (repo-wide subprocess rule). Returns (rc, stdout, stderr);
    a timeout or spawn failure becomes rc=None + the error in stderr, which callers
    record and survive (one broken tool must not kill the run)."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return None, "", "TOOL_TIMEOUT after %ss" % timeout
    except OSError as e:
        return None, "", "%s: %s" % (type(e).__name__, e)


def _api_opener() -> urllib.request.OpenerDirector:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # engagement boxes run intercepting proxies (sibling precedent)
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


_OPENER = _api_opener()


def github_code_search(query: str, token: str, timeout: float) -> dict:
    """One authenticated code-search request (the ONLY HTTP seam in this script — tests
    patch this function). Unauthenticated code search returns zero results (recon.md
    §4), so this must never be called without a token. Returns
    {ok, status, rate_limited, total_count, items, error}: 403/422 are the code-search
    rate/abuse limits — flagged rate_limited, recorded by the caller, never retried."""
    url = (SEARCH_ENDPOINT + "?q=" + urllib.parse.quote(query, safe="")
           + "&per_page=%d" % PER_PAGE)
    req = urllib.request.Request(url, headers={**API_HEADERS,
                                               "Authorization": "Bearer " + token})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_API_RESPONSE_BYTES + 1)
            data = json.loads(raw[:MAX_API_RESPONSE_BYTES].decode("utf-8", "replace"))
        items = data.get("items") if isinstance(data, dict) else None
        items = items if isinstance(items, list) else []
        total = data.get("total_count") if isinstance(data, dict) else None
        return {"ok": True, "status": 200, "rate_limited": False, "error": None,
                "total_count": int(total) if isinstance(total, int) else len(items),
                "items": items}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(512).decode("utf-8", "replace")
        except Exception:
            pass
        limited = e.code in (403, 422) or "rate limit" in body.lower()
        return {"ok": False, "status": e.code, "rate_limited": limited,
                "total_count": 0, "items": [],
                "error": "HTTP %s%s" % (e.code, (": " + body.strip()) if body else "")}
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as e:
        return {"ok": False, "status": None, "rate_limited": False,
                "total_count": 0, "items": [], "error": "%s: %s" % (type(e).__name__, e)}


# --------------------------------------------------------------------------
# recon.md §4 dork list — the doc's exact queries, TARGETORG/TARGET.com -> --org/--domain
# --------------------------------------------------------------------------

def build_dorks(org: str | None, domain: str | None) -> list[str]:
    """recon.md §4's list, in the doc's order: org dork, domain dorks, final org dork.
    Only the dorks scopeable to what was actually given are built."""
    dorks: list[str] = []
    if org:
        dorks.append('org:%s "password"|"secret"|"api_key"|"apikey"|"token"|'
                     '"BEGIN RSA PRIVATE KEY"' % org)
    if domain:
        dorks.append('"%s" AKIA' % domain)
        dorks.append('"%s" password' % domain)
        dorks.append('"%s" filename:.env' % domain)
        dorks.append('"%s" filename:config extension:json' % domain)
        dorks.append('"%s" "authorization: bearer"' % domain)
        dorks.append('"internal" "%s" filename:.npmrc' % domain)
    if org:
        dorks.append('org:%s language:yaml "aws_secret_access_key"' % org)
    return dorks


# --------------------------------------------------------------------------
# source: trufflehog (JSONL -> secret findings; Raw parsed ONLY to be scrubbed)
# --------------------------------------------------------------------------

def parse_trufflehog_jsonl(text: str) -> tuple[list[dict], int]:
    """One JSON object per line; unparseable lines are counted, never fatal."""
    out: list[dict] = []
    bad = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out, bad


def _trufflehog_gitmeta(obj: dict) -> dict:
    """Defensive walk of SourceMetadata.Data.Git (older shapes put fields straight
    under Data). Never trusted — every field defaults to '(unknown)'."""
    data = (obj.get("SourceMetadata") or {}).get("Data") or {}
    git = data.get("Git")
    if not isinstance(git, dict):
        git = data if isinstance(data, dict) else {}
    return git


def _secret_hit_finding(tool: str, detector: str, verified: bool, repo: str,
                        path: str, line, commit: str, scrub_fn) -> dict:
    """ONE normalized secret finding. Raw/Secret values are never passed in here at
    all — callers hand only metadata fields; the scrub_fn safety net covers evidence
    strings anyway (defense in depth)."""
    if tool == "trufflehog" and verified:
        severity, conf = "high", 0.90
        verdict = ("VERIFIED LIVE by trufflehog against the actual provider API — real "
                   "evidence, not a regex match; this is the one automated 'high' this "
                   "repo's scripts emit")
        next_action = ("credential is live — treat as INCIDENT-grade: rotate/revoke it "
                       "NOW with the owning team, then record per validate.md before any "
                       "report; the raw value is in the source repo (not echoed here)")
    else:
        severity, conf = "medium", 0.65
        verdict = "detector matched, NOT live-verified — confirm before reporting"
        next_action = ("open %s, confirm the value is a real credential and not an "
                       "example/placeholder, then validate live per validate.md "
                       "(re-run trufflehog with verification ON — this script's default — "
                       "or check the provider console); do NOT report as confirmed until "
                       "validated" % (path or repo or "the flagged file"))
    loc = "%s @ %s" % (repo or "(repo unknown)", path or "(file unknown)")
    if line not in (None, "", 0):
        loc += ":%s" % line
    evidence = [
        "tool=%s detector=%s verified=%s" % (tool, detector or "(unknown)", str(verified).lower()),
        verdict,
        "repo=%s file=%s line=%s commit=%s" % (repo or "(unknown)", path or "(unknown)",
                                               line if line not in (None, "") else "(unknown)",
                                               commit or "(unknown)"),
        "raw secret value OMITTED from this evidence per findings discipline "
        "(no secrets in findings/) — it is in the flagged file itself",
    ]
    finding = {"type": "github_secret_hit", "severity": severity, "confidence": conf,
               "target": loc, "evidence": [scrub_fn(e) for e in evidence],
               "source": SOURCE, "tool": tool, "detector": detector or "(unknown)",
               "verified": bool(verified), "next_action": scrub_fn(next_action)}
    return finding


def run_trufflehog(tool_path: str, org: str, token: str, timeout: float,
                   scrub_fn, verbose: bool = False) -> tuple[list[dict], list[str], list[str]]:
    """Org-wide scan. Verification stays ON (the default, and the point). rc != 0 with
    partial stdout still parses what streamed before the failure — trufflehog emits
    results progressively, so losing the tail must not discard the head."""
    argv = [tool_path, "github", "--org=%s" % org, "--json", "--token=%s" % token,
            "--results=verified,unverified"]
    if verbose:
        eprint("  [trufflehog] running org scan (verification ON, this can take minutes)")
    rc, out, err = run_tool(argv, TOOL_TIMEOUT_S)
    evidence: list[str] = []
    errors: list[str] = []
    findings: list[dict] = []

    results, bad_lines = parse_trufflehog_jsonl(out)
    evidence.append("trufflehog: org=%s verification=ON (live provider-API check is the "
                    "point; see module docstring)" % org)
    if rc == 0:
        evidence.append("trufflehog: completed (rc=0)")
    elif rc is None:
        errors.append("trufflehog: %s" % scrub_fn(err))
        evidence.append("trufflehog: %s" % scrub_fn(err))
    else:
        errors.append("trufflehog: rc=%s %s" % (rc, scrub_fn(err.strip()[:300])))
        evidence.append("trufflehog: exited rc=%s — results streamed before the failure "
                        "were still parsed" % rc)
    if bad_lines:
        evidence.append("trufflehog: %d unparseable stdout line(s) skipped" % bad_lines)

    seen: set = set()
    for obj in results:
        git = _trufflehog_gitmeta(obj)
        detector = obj.get("DetectorName") or "(unknown)"
        verified = bool(obj.get("Verified"))
        raw = obj.get("Raw")
        finding = _secret_hit_finding(
            "trufflehog", detector, verified,
            git.get("repository") or git.get("repo") or "",
            git.get("file") or "", git.get("line"), git.get("commit") or "",
            make_scrubber(*( [raw] if isinstance(raw, str) else [] ), token))
        key = (finding["target"], detector, verified)
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)
        evidence.append("trufflehog: secret hit detector=%s verified=%s at %s (value "
                        "redacted)" % (finding["detector"], str(verified).lower(),
                                       finding["target"]))
    if not results and rc == 0:
        evidence.append("trufflehog: ran clean — 0 result(s) in org %s (a real scan, "
                        "not a skip: see metadata.sources_run)" % org)
    return findings, evidence, errors


# --------------------------------------------------------------------------
# source: gitleaks (LOCAL repo only — this script never clones; --local-repo opt-in)
# --------------------------------------------------------------------------

def parse_gitleaks_report(path: str) -> list[dict]:
    """gitleaks v8 --report-format json: a bare array of findings (defensively also
    accepts {"findings": [...]}). Missing/unreadable report -> []."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [d for d in data["findings"] if isinstance(d, dict)]
    return []


def run_gitleaks(tool_path: str, local_repo: str, token: str | None,
                 scrub_fn, verbose: bool = False) -> tuple[list[dict], list[str], list[str]]:
    """Scan an ALREADY-cloned local repo (--no-git, per the confirmed CLI syntax).
    gitleaks exits rc=1 when leaks are found — expected, recorded as such, not an
    error. Report goes to a temp file, parsed, then removed."""
    evidence: list[str] = []
    errors: list[str] = []
    findings: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="moraa-gitleaks-") as td:
        report = str(Path(td) / "gitleaks_report.json")
        argv = [tool_path, "detect", "--no-git", "-s", local_repo,
                "--report-format", "json", "--report-path", report]
        if verbose:
            eprint("  [gitleaks] scanning local repo %s (--no-git)" % local_repo)
        rc, out, err = run_tool(argv, TOOL_TIMEOUT_S)
        evidence.append("gitleaks: local repo=%s mode=--no-git (working tree only, not "
                        "history — clone + full-history scan is a deliberate manual step)"
                        % local_repo)
        if rc in (0, 1):
            evidence.append("gitleaks: completed (rc=%d%s)"
                            % (rc, " = leaks found (gitleaks' expected exit)" if rc else ""))
        elif rc is None:
            errors.append("gitleaks: %s" % scrub_fn(err))
            return findings, evidence, errors
        else:
            errors.append("gitleaks: rc=%s %s" % (rc, scrub_fn(err.strip()[:300])))

        leaks = parse_gitleaks_report(report)
        if rc == 1 and not leaks:
            # rc=1 means gitleaks FOUND leaks; a missing/unreadable report then is not
            # a clean zero — say so instead of letting it pass as "ran and found none"
            errors.append("gitleaks: signaled leaks (rc=1) but the report at %s could "
                          "not be read/parsed — re-run gitleaks detect manually on %s "
                          "to recover them" % (report, local_repo))
        evidence.append("gitleaks: %d finding(s) in report; Secret values parsed ONLY to "
                        "be scrubbed from this output" % len(leaks))
        seen: set = set()
        for leak in leaks:
            rule = leak.get("RuleID") or leak.get("Description") or "(unknown rule)"
            file = leak.get("File") or "(unknown file)"
            line = leak.get("StartLine")
            commit = leak.get("Commit") or ""
            secret = leak.get("Secret") if isinstance(leak.get("Secret"), str) else None
            scrub_hit = make_scrubber(secret or "", token)
            finding = _secret_hit_finding(
                "gitleaks", str(rule), False, local_repo, file, line, commit, scrub_hit)
            key = (file, line, rule)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
            evidence.append("gitleaks: hit rule=%s at %s:%s (value redacted)"
                            % (rule, file, line if line is not None else "?"))
    return findings, evidence, errors


# --------------------------------------------------------------------------
# source: github-subdomains (domain-scoped recon output -> ONE info summary finding)
# --------------------------------------------------------------------------

def parse_subdomain_lines(text: str) -> tuple[list[str], int]:
    """Line-per-subdomain stdout; hostname-shaped lines only (tool banners/progress
    lines are dropped and counted, never parsed as data). Deduped, order kept."""
    subs: list[str] = []
    dropped = 0
    seen: set = set()
    for line in text.splitlines():
        s = line.strip().lower().rstrip(".")
        if not s:
            continue
        if HOSTNAME_RE.match(s) and "." in s:
            if s not in seen:
                seen.add(s)
                subs.append(s)
        else:
            dropped += 1
    return subs, dropped


def run_github_subdomains(tool_path: str, domain: str, token: str, timeout: float,
                          scrub_fn, verbose: bool = False) -> tuple[list[dict], list[str], list[str], list[str]]:
    """Returns (findings, evidence, errors, subdomains). The summary is recon output
    (js_recon.js_endpoint_summary pattern), not a vulnerability finding."""
    argv = [tool_path, "-d", domain, "-t", token, "-raw"]
    if verbose:
        eprint("  [github-subdomains] searching GitHub code for %s hosts" % domain)
    rc, out, err = run_tool(argv, TOOL_TIMEOUT_S)
    evidence: list[str] = []
    errors: list[str] = []
    if rc is None:
        errors.append("github-subdomains: %s" % scrub_fn(err))
        return [], evidence, errors, []   # failed run: never emit a fake-clean "0 found"
    subs, dropped = parse_subdomain_lines(out)
    evidence.append("github-subdomains: domain=%s — %d unique subdomain(s) mentioned in "
                    "GitHub code%s" % (domain, len(subs),
                                       ", %d non-hostname stdout line(s) dropped" % dropped
                                       if dropped else ""))
    if rc != 0:
        errors.append("github-subdomains: rc=%s %s" % (rc, scrub_fn(err.strip()[:300])))
        evidence.append("github-subdomains: nonzero rc — NO summary finding emitted (a "
                        "failed run must not look like a clean zero-result sweep)")
        return [], evidence, errors, []
    shown = subs[:40]
    evidence.append("subdomains (%d): %s%s" % (
        len(subs), ", ".join(shown) if shown else "(none)",
        " … (+%d more)" % (len(subs) - 40) if len(subs) > 40 else ""))
    evidence.append("github-subdomains: completed (rc=0) — summary below is recon "
                    "output, not a vulnerability finding")
    finding = {
        "type": "github_subdomain_summary", "severity": "info", "confidence": 0.90,
        "target": domain,
        "evidence": scrub_list(evidence, scrub_fn),
        "source": SOURCE, "subdomains_found": list(subs),
        "next_action": ("recon output, NOT a vulnerability: feed the new hosts into "
                        "recon.md §1 resolve->live->fingerprint (dnsx/httpx), then §2 — "
                        "and cross-check them against the §4 internal-host dorks"),
    }
    return [finding], evidence, errors, subs


def scrub_list(items: list[str], scrub_fn) -> list[str]:
    return [scrub_fn(i) for i in items]


# --------------------------------------------------------------------------
# source: GitHub code-search dork sweep (recon.md §4, authenticated, rate-limit aware)
# --------------------------------------------------------------------------

def run_dork_sweep(dorks: list[str], token: str, timeout: float, sleep_s: float,
                   scrub_fn, verbose: bool = False) -> tuple[list[dict], list[str], list[str], list[dict], list[str]]:
    """One code-search call per dork, sequential, small sleep between calls (10 req/min
    limit). 403/422 -> recorded as rate-limited, sweep CONTINUES (no retries, no
    hammering). Findings are per-dork and low severity: this script knows a dork
    matched, not what the file contains — opening the file is a human next step."""
    findings: list[dict] = []
    evidence: list[str] = []
    errors: list[str] = []
    dork_stats: list[dict] = []
    rate_limited: list[str] = []
    for i, query in enumerate(dorks):
        if i and sleep_s > 0:
            time.sleep(sleep_s)
        if verbose:
            eprint("  [dorks] (%d/%d) %s" % (i + 1, len(dorks), query))
        r = github_code_search(query, token, timeout)
        if r["ok"]:
            items = r["items"]
            hits = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                repo = (item.get("repository") or {}).get("full_name") or "(unknown repo)"
                hits.append({"repo": repo, "path": item.get("path") or "(unknown path)",
                             "name": item.get("name") or "", "html_url": item.get("html_url") or ""})
            dork_stats.append({"query": query, "status": "ok", "hits": len(hits),
                               "total_count": r["total_count"]})
            if not hits:
                evidence.append("dork: %s -> 0 hits" % query)
                continue
            ev_lines = ["dork: %s -> %d hit(s)" % (query, len(hits))]
            for h in hits[:MAX_HITS_EVIDENCE]:
                ev_lines.append("  %s — %s (%s)" % (h["repo"], h["path"], h["name"]))
            if len(hits) > MAX_HITS_EVIDENCE:
                ev_lines.append("  … (+%d more in finding.hits)" % (len(hits) - MAX_HITS_EVIDENCE))
            if r["total_count"] > len(hits):
                ev_lines.append("  GitHub total_count=%d, first page only (%d shown) — "
                                "paginate manually if promising" % (r["total_count"], len(hits)))
            findings.append({
                "type": "github_dork_hit", "severity": "low", "confidence": 0.50,
                "target": query, "evidence": [scrub_fn(e) for e in ev_lines],
                "source": SOURCE, "hits": hits,
                "next_action": ("dork matched — this script did NOT read the file(s): "
                                "manually open the hits above, look for real secrets/"
                                "internal hosts, and validate anything live per "
                                "validate.md before reporting"),
            })
            evidence.append("dork: %s -> %d hit(s) (low finding emitted)" % (query, len(hits)))
        elif r["rate_limited"]:
            dork_stats.append({"query": query, "status": "rate_limited", "hits": 0,
                               "total_count": 0})
            rate_limited.append(query)
            evidence.append("dork: %s -> RATE-LIMITED/abstained (HTTP %s) — recorded, not "
                            "retried; sweep continues (code search is 10 req/min even "
                            "authenticated)" % (query, r["status"]))
        else:
            dork_stats.append({"query": query, "status": "error", "hits": 0,
                               "total_count": 0})
            errors.append("dork: %s -> %s" % (query, scrub_fn(r["error"] or "unknown error")))
    return findings, evidence, errors, dork_stats, rate_limited


# --------------------------------------------------------------------------
# the orchestrator
# --------------------------------------------------------------------------

SOURCE_NAMES = ("trufflehog", "gitleaks", "github-subdomains", "github_dork_sweep")


def scan_github(org: str | None = None, domain: str | None = None, token: str | None = None,
                token_source: str | None = None, local_repo: str | None = None,
                timeout: float = DEFAULT_TIMEOUT, sleep_s: float | None = None,
                verbose: bool = False) -> dict:
    """Run every source that CAN run given (tools installed, token, --local-repo), skip
    the rest with explicit reasons, normalize into ONE aggregate result object."""
    if sleep_s is None:
        sleep_s = DORK_QUERY_SLEEP_S
    scope = " ".join(p for p in ("org:%s" % org if org else None,
                                 "domain:%s" % domain if domain else None) if p)
    scrub = make_scrubber(token)  # baseline scrubber: the token itself never lands anywhere
    findings: list[dict] = []
    evidence: list[str] = ["scope: %s" % scope]
    errors: list[str] = []
    sources_run: list[str] = []
    sources_skipped: list[dict] = []
    subdomains: list[str] = []
    dork_stats: list[dict] = []
    rate_limited: list[str] = []

    # ---- trufflehog (needs: installed + --org + token) --------------------------
    tp = find_tool("trufflehog")
    if tp is None:
        sources_skipped.append({
            "source": "trufflehog",
            "reason": "not installed (find_tool checked PATH + %s) — install: "
                      "go install github.com/trufflesecurity/trufflehog/v3@latest"
                      % ", ".join(EXTRA_TOOL_DIRS)})
    elif token is None:
        sources_skipped.append({
            "source": "trufflehog",
            "reason": "installed but no GH_TOKEN (checked --token, $GH_TOKEN, "
                      "~/.moraa/config.json) — authenticated org scan requires a token"})
    elif org is None:
        sources_skipped.append({
            "source": "trufflehog",
            "reason": "installed + token present but --org not given — trufflehog github "
                      "scans an org (--org=) or explicit repos (--repo=); for domain-only "
                      "targets rely on the dork sweep, or clone a repo yourself and use "
                      "--local-repo for gitleaks"})
    else:
        sources_run.append("trufflehog")
        f, e, errs = run_trufflehog(tp, org, token, timeout, scrub, verbose)
        findings.extend(f)
        evidence.extend(scrub(x) for x in e)
        errors.extend(errs)

    # ---- gitleaks (needs: installed + --local-repo; no token required) ----------
    gl = find_tool("gitleaks")
    if gl is None:
        sources_skipped.append({
            "source": "gitleaks",
            "reason": "not installed (find_tool checked PATH + %s) — install: "
                      "go install github.com/zricethezav/gitleaks/v8@latest"
                      % ", ".join(EXTRA_TOOL_DIRS)})
    elif local_repo is None:
        sources_skipped.append({
            "source": "gitleaks",
            "reason": "installed but --local-repo not given — gitleaks scans a LOCAL "
                      "directory only and this script never clones org repos "
                      "automatically (too broad/risky an action for a read-only recon "
                      "sweep); clone the repo you want deep-scanned yourself, then "
                      "re-run with --local-repo <path>"})
    else:
        sources_run.append("gitleaks")
        f, e, errs = run_gitleaks(gl, local_repo, token, scrub, verbose)
        findings.extend(f)
        evidence.extend(scrub(x) for x in e)
        errors.extend(errs)

    # ---- github-subdomains (needs: installed + --domain + token) ----------------
    gs = find_tool("github-subdomains")
    if gs is None:
        sources_skipped.append({
            "source": "github-subdomains",
            "reason": "not installed (find_tool checked PATH + %s) — install: "
                      "go install github.com/gwen001/github-subdomains@latest"
                      % ", ".join(EXTRA_TOOL_DIRS)})
    elif token is None:
        sources_skipped.append({
            "source": "github-subdomains",
            "reason": "installed but no GH_TOKEN (checked --token, $GH_TOKEN, "
                      "~/.moraa/config.json) — it searches GitHub code, which needs an "
                      "authenticated token"})
    elif domain is None:
        sources_skipped.append({
            "source": "github-subdomains",
            "reason": "installed + token present but --domain not given — it is "
                      "domain-scoped (-d)"})
    else:
        sources_run.append("github-subdomains")
        f, e, errs, subs = run_github_subdomains(gs, domain, token, timeout, scrub, verbose)
        findings.extend(f)
        evidence.extend(scrub(x) for x in e)
        errors.extend(errs)
        subdomains.extend(subs)

    # ---- GitHub code-search dork sweep (needs: token; org/domain scoped) --------
    dorks = build_dorks(org, domain)
    if token is None:
        sources_skipped.append({
            "source": "github_dork_sweep",
            "reason": "no GH_TOKEN (checked --token, $GH_TOKEN, ~/.moraa/config.json) — "
                      "unauthenticated code search returns ZERO results (recon.md §4), "
                      "so the sweep is skipped rather than run pointlessly"})
    else:
        sources_run.append("github_dork_sweep")
        f, e, errs, dork_stats, rate_limited = run_dork_sweep(
            dorks, token, timeout, sleep_s, scrub, verbose)
        findings.extend(f)
        evidence.extend(scrub(x) for x in e)
        errors.extend(errs)

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    return {
        "tool": TOOL,
        "target": scope,
        "timestamp": now_iso(),
        "status": "success",
        "findings": findings,
        "evidence": evidence,
        "errors": errors,
        "metadata": {
            "org": org,
            "domain": domain,
            "token_source": token_source,   # presence/source only — never the value
            "sources_run": sources_run,
            "sources_skipped": sources_skipped,
            "dorks": dork_stats,
            "rate_limited_dorks": rate_limited,
            "subdomains_found": subdomains,
            "gitleaks_local_repo": local_repo,
            "trufflehog_verification": "on (live provider-API verification — default, "
                                       "and the whole point of trufflehog)",
            "timeout_api_s": timeout,
            "timeout_tool_s": TOOL_TIMEOUT_S,
            "totals": {
                "findings_by_severity": by_sev,
                "dorks_built": len(dorks),
                "dorks_run": len(dork_stats),
                "dorks_rate_limited": len(rate_limited),
                "dork_hits": sum(d["hits"] for d in dork_stats),
                "subdomains": len(subdomains),
            },
        },
    }


# --------------------------------------------------------------------------
# CLI (conventions shared with cms_detect.py / js_recon.py / cors_check.py /
# exposure_sweep.py)
# --------------------------------------------------------------------------

def print_human(result: dict, quiet: bool) -> None:
    if quiet:
        return
    md = result["metadata"]
    eprint("[*] sources run: %s" % (", ".join(md["sources_run"]) or "(none)"))
    for s in md["sources_skipped"]:
        eprint("[skip] %s — %s" % (s["source"], s["reason"]))
    for f in result["findings"]:
        eprint("[%s] %s/%s (confidence %.2f) — %s" % (
            f["target"], f["severity"].upper(), f["type"], f["confidence"],
            f["next_action"].split(". ")[0]))
    for err in result["errors"]:
        eprint("ERROR: %s" % err)
    totals = md["totals"]
    eprint("")
    eprint("totals: %d finding(s) %s | dorks: %d built, %d run, %d rate-limited | "
           "subdomains: %d" % (
               len(result["findings"]), totals["findings_by_severity"] or "(all clean)",
               totals["dorks_built"], totals["dorks_run"], totals["dorks_rate_limited"],
               totals["subdomains"]))
    eprint("")
    eprint("Next: for every github_secret_hit, follow next_action — verified=high means "
           "rotate/revoke NOW; unverified/medium means open the file and confirm before "
           "reporting. Open github_dork_hit files MANUALLY (this script never fetched "
           "them), feed subdomains into recon.md §1, and record the sweep in coverage.md")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=SOURCE,
        description="GitHub/code-recon ORCHESTRATOR (recon.md §4): wraps trufflehog "
                    "(org-wide secret scan, live verification ON), gitleaks (an "
                    "ALREADY-cloned local repo via --local-repo — this script never "
                    "clones), github-subdomains (domain hosts in GitHub code), and the "
                    "authenticated GitHub code-search dork sweep (10 req/min — spaced, "
                    "403/422 recorded not retried). NOT a secret-scanning engine — it "
                    "normalizes whatever sources actually ran into the repo JSON "
                    "contract and says exactly which sources were skipped and why. "
                    "Secret VALUES never appear in findings (detector/repo/file/line/"
                    "verified only).",
        epilog="examples:\n"
               "  %(prog)s --org targetorg --json\n"
               "  %(prog)s --org targetorg --domain target.com --json --output gh.json\n"
               "  %(prog)s --domain target.com --local-repo ~/clones/target-api --verbose\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", metavar="ORG",
                    help="GitHub org to scope trufflehog (--org=) and the org: dorks")
    ap.add_argument("--domain", metavar="DOMAIN",
                    help="domain to scope the code-search dorks and github-subdomains")
    ap.add_argument("--token", metavar="TOKEN",
                    help="GitHub token (default: $GH_TOKEN, then the GH_TOKEN key in "
                         "~/.moraa/config.json — lib/config.sh convention)")
    ap.add_argument("--local-repo", metavar="PATH",
                    help="an ALREADY-cloned repo directory for the gitleaks stage "
                         "(gitleaks cannot scan a GitHub org directly, and this script "
                         "will not clone for you)")
    ap.add_argument("--json", action="store_true",
                    help="machine output on stdout (normalized JSON; ONE object per run)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SEC",
                    help="per-GitHub-API-call timeout in seconds (default: 10; wrapped "
                         "tools get their own longer cap, see metadata.timeout_tool_s)")
    ap.add_argument("--output", metavar="FILE",
                    help="also write the JSON result to this file")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress the human-readable summary (no effect with --json)")
    ap.add_argument("--verbose", action="store_true",
                    help="print each source's progress to stderr as it runs")
    args = ap.parse_args(argv)

    if not args.org and not args.domain:
        ap.error("at least one of --org / --domain is required")
    if args.timeout <= 0:
        ap.error("--timeout must be > 0")
    if args.local_repo and not Path(args.local_repo).is_dir():
        eprint("[!] --local-repo is not an existing directory: %s" % args.local_repo)
        return 2

    token, token_source = get_github_token(args.token)
    if token is None and not args.quiet and not args.json:
        eprint("[*] no GH_TOKEN found (env / ~/.moraa/config.json) — token-dependent "
               "sources will be skipped with reasons")

    if not args.quiet and not args.json:
        eprint("[*] %s: org=%s domain=%s | token: %s | api timeout: %ss | "
               "tool timeout: %ss | dork spacing: %ss" % (
                   TOOL, args.org or "-", args.domain or "-",
                   token_source or "NONE", args.timeout, int(TOOL_TIMEOUT_S),
                   DORK_QUERY_SLEEP_S))

    result = scan_github(org=args.org, domain=args.domain, token=token,
                         token_source=token_source, local_repo=args.local_repo,
                         timeout=args.timeout, verbose=args.verbose)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_human(result, quiet=args.quiet)

    if args.output:
        try:
            Path(args.output).write_text(json.dumps(result, indent=2) + "\n",
                                         encoding="utf-8")
            if not args.quiet and not args.json:
                eprint("[*] JSON written to %s" % args.output)
        except OSError as e:
            eprint(f"[!] failed to write {args.output}: {e}")
            return 2

    return 0  # completed scan — every-source-skipped is a valid outcome, not an error


if __name__ == "__main__":
    sys.exit(main())
