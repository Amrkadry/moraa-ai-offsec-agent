#!/usr/bin/env python3
"""exposure_sweep.py — source/config disclosure sweeper (recon.md §4d pipeline, zero pip deps).

WHY: recon.md §4d's triage sweep (`.git/HEAD`, `.env`, `.svn/wc.db`, `.DS_Store`, backups...)
is currently a hand-run nested bash for-loop per engagement. This script automates that
section, verbatim, in two tiers over a whole recon/live.txt-style host list in one run:

    HOST LIST -> TIER 1 TRIAGE SWEEP (§4d's exact 14-path "fire against every live host
                first" list — one bounded GET per path per host; 200 = HIT, everything
                else = a counted miss, never an evidence line)
              -> TIER 2 ENV/CONFIG-BY-STACK (§4d's table, minus tier-1 overlap — only the
                5 paths the table adds: /.env.production /connectionStrings.config
                /appsettings.json /secrets.json /wp-config.php)
              -> PER-HIT EVALUATION: is the 200 genuinely the expected file type? does the
                body carry secrets? (two separate signals, below)
              -> POST-PROCESSING: /.git/HEAD -> origin-remote extraction from /.git/config
                (credentialed remote = its own distinct finding); /.DS_Store -> best-effort
                filename extraction
              -> DEDUPED AGGREGATE (one result object for the whole batch)

Severity ladder — recon.md §4d's OWN ladder, verbatim, never invented:
    path returns 200 (no further signal)            -> info
    genuine source/config file recovered (200 AND
      the body matches the expected file format,
      e.g. .git/HEAD starts with "ref: refs/")      -> low
    + verified secret pattern                       -> high
Never "critical": §4d's ladder tops out at High for this technique and this script keeps
that. The one candidate for more — a git remote URL with embedded plaintext credentials —
stays high but gets its OWN distinct finding (variant git_remote_credential, confidence
0.85, password redacted in evidence): see the comment at CONF_REMOTE_CREDS for why it is
categorically worse than a generic regex match yet still not auto-critical.

Two separate secret signals per the §4d text, never merged:
  1. SECRET_PATTERNS — the js-analysis.md §2 regex set with its own tiering, IMPORTED from
     scripts/js_recon.py (third definition of that list in this repo would be a maintenance
     bug; this is an intra-repo import, not a pip dependency). Any high/medium-tier kind
     hit escalates the finding to high; a low-tier kind (firebase_reference-style,
     public-by-design) only annotates evidence — it must not pad a file to high.
  2. The doc's own broader catch-all grep, verbatim:
     password|secret|api[_-]?key|aws|jdbc|connectionstring|begin .*private key (-iE).
     A phrase hit without a SECRET_PATTERNS hit is still recorded — at deliberately LOW
     confidence (0.45) — because the §4d ladder's high tier requires a verified secret
     *pattern*, and a generic word is an indicator, not a pattern. So phrase-only hits keep
     the file's base severity (low/info) and carry the uncertainty in confidence +
     next_action ("open the file and confirm a real secret before treating as High") rather
     than inventing a mid-tier severity the doc doesn't have. On HTML-looking bodies the
     phrase signal is suppressed entirely (a login form legitimately contains "password");
     SECRET_PATTERNS still runs on everything.

Honesty guards baked in (the ways this class of scanner lies, each with a countermeasure):
  - catch-all/soft-200 servers (recon.md §6: "everything returns index.html/200") fabricate
    hits. One extra GET of the site root per host; any hit whose body matches the root
    (or whose body repeats across >= 3 probed paths) is annotated as a likely catch-all and
    can never look more confirmed than a plain 200. Genuine-file signatures are the primary
    guard — "ref: refs/" does not appear in index.html.
  - a 200 reached only after redirects is annotated with the redirect chain (redirect-to-
    generic-page 200s are a classic false HIT).
  - an over-cap body is NOT silently truncated away: the first MAX_BODY_BYTES still prove
    exposure and still get swept, and the finding says explicitly that bytes beyond the cap
    went unexamined (unlike js_recon, where a short pull voids the whole read — there the
    size assertion IS the product; here detection from the head of the file is enough).
  - "low" means "a real source/config file was recovered", NOT "this is definitely sensitive
    app logic" — vendored framework code with no secrets/app-logic is Info at best (§4d's
    own caveat), and every low finding says so in evidence/next_action. This script is a
    DETECTOR, not git-dumper: repo reconstruction is delegated to the §4d tools in
    next_action (git-dumper / sqlite3 / dvcs-ripper), never attempted here.

.DS_Store extraction is BEST-EFFORT AND LOSSY by design: the zero-pip-deps repo rule bans
the `pip install ds-store` parser, so filenames come from a strings(1)-style printable-ASCII
scan plus a UTF-16BE-shaped scan (the on-disk format stores names as UTF-16BE, which a plain
strings pass reads as junk) — no tree structure, no record semantics, and an uncommon 4-char
record type code can leak through the filter. That is exactly recon.md §4d's own fallback
posture (`curl -s .../.DS_Store | strings | sort -u`); run ds_store_exp.py manually for the
full recursive map.

HTTP client: js_recon.http_fetch, IMPORTED (not a fourth divergent client — same bounded
reads, capped hop-logged redirects, TLS-verify-off-for-intercepting-proxies lineage as
cms_detect.probe_http), called with this script's own body cap and User-Agent:
- BODY CAP: subdomain_takeover/cms_detect/cors_check cap at 64KB because fingerprint/CORS
  responses are tiny; js_recon allows up to 512MB because it mines whole JS bundles under a
  hard assembled-size assertion. This script reads source/config disclosures: .env,
  web.config, application.properties, config.php.bak are almost always < 100KB, but source
  dumps and backup archives can reach MBs — MAX_BODY_BYTES (1MB) keeps the secret sweep
  meaningful without buffering a whole site across an entire live.txt batch.
- OVER-CAP SEMANTICS: flagged, not fatal (see honesty guards above).

Scope discipline: read-only GETs against the fixed §4d path list on hosts YOU are authorized
to test. No brute force, no wordlists, no repo reconstruction.

Usage:
    python3 exposure_sweep.py https://host [more-hosts ...]
    python3 exposure_sweep.py -l recon/live.txt --json --output exposure.json
    python3 exposure_sweep.py -l recon/live.txt --threads 20 --verbose

Exit code: 0 for a completed scan (every host failing is still a completed scan — failures
land in errors[]), non-zero only for hard errors (bad args, missing/unreadable -l file).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import sys
import urllib.parse
from pathlib import Path

from js_recon import SECRET_PATTERNS, http_fetch, mine_text, now_iso

TOOL = "exposure_sweep"
SOURCE = "exposure_sweep.py"

USER_AGENT = "Mozilla/5.0 (compatible; moraa-exposuresweep/1.0; authorized-scope-use-only)"

# recon.md §4d triage sweep — the doc's exact "fire against every live host first" list,
# in the doc's order. Verbatim; do not extend here (new paths belong in the doc first).
TIER1_PATHS = [
    "/.git/HEAD", "/.git/config", "/.git/logs/HEAD", "/.svn/wc.db", "/.svn/entries",
    "/.hg/requires", "/.bzr/branch-format", "/.DS_Store", "/.env", "/web.config",
    "/WEB-INF/web.xml", "/application.properties", "/config.php.bak", "/backup.zip",
]
# recon.md §4d env/config-leak-by-stack table — ONLY the rows tier 1 does not already
# cover (the table's /.env, /web.config, /WEB-INF/web.xml and /application.properties
# rows are tier-1 paths; re-requesting them would double-probe .env, the exact waste
# the task calls out). /config.php (executed, not disclosed) is not in either tier.
TIER2_PATHS = [
    "/.env.production", "/connectionStrings.config", "/appsettings.json",
    "/secrets.json", "/wp-config.php",
]
assert not (set(TIER1_PATHS) & set(TIER2_PATHS)), \
    "tier-2 must never re-probe a tier-1 path (recon.md §4d dedupe rule)"
ALL_PATHS = [("tier 1", p) for p in TIER1_PATHS] + [("tier 2", p) for p in TIER2_PATHS]

# WHY 1MB and not the siblings' caps: see module docstring ("BODY CAP"). Config/source
# disclosures are KB-scale; source dumps / backup archives can be MBs; a live.txt batch
# must not buffer whole sites. Over-cap reads are flagged in evidence, never silent.
MAX_BODY_BYTES = 1 * 1024 * 1024
ROOT_PROBE_BYTES = 64 * 1024    # catch-all comparison only — the root page is not mined

DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 10            # OUTER loop: hosts swept concurrently; each host's path
                                # sweep stays sequential so evidence order is deterministic

# recon.md §4d's own catch-all grep, verbatim ("per the doc's own grep pattern"):
#   grep -iqE "password|secret|api[_-]?key|aws|jdbc|connectionstring|begin .*private key"
SECRET_PHRASE_RE = re.compile(
    r"password|secret|api[_-]?key|aws|jdbc|connectionstring|begin .*private key",
    re.IGNORECASE)
# recon.md §4d .DS_Store section's interesting-filename grep, verbatim.
DSSTORE_INTEREST_RE = re.compile(r"backup|admin|config|\.sql|\.zip|\.bak|internal|test",
                                 re.IGNORECASE)
# JS frameworks' "X-Generated-By: index.html for everything" tell (recon.md §6 catch-all).
HTMLISH_RE = re.compile(r"<html[\s>]|<!doctype\s+html", re.IGNORECASE)

# confidence constants — severity comes from the §4d ladder; confidence carries the
# residual uncertainty each signal leaves (never over-claim from one weak signal).
CONF_BARE_200 = 0.60            # 200 only, no format confirmation (could be a soft-200)
CONF_GENUINE = 0.85             # body matches the expected file format for the path
CONF_PHRASE = 0.45              # catch-all phrase grep only — deliberately LOW
CONF_PATTERN_TIER = {"high": 0.80, "medium": 0.70, "low": 0.40}  # by js_recon kind tier
CONF_REMOTE_CREDS = 0.85
# NO critical tier on purpose — see the ladder comment in the module docstring. The
# tempting escalation is a git remote with embedded plaintext creds, which IS categorically
# worse than a generic regex-shaped match (user:pass@ is a complete, directly-usable
# credential string, not a half-of-a-credential key ID). But "live-looking" in an abandoned
# .git/config is routinely stale/rotated, so it gets severity=high + its own distinct
# finding + the validate.md gate in next_action instead of an auto-critical the operator
# would then have to talk down. Categorical-worse-ness is expressed as a separate finding,
# not severity inflation.

DSSTORE_MAGIC = b"\x00\x00\x00\x01Bud1"
# 4-char record type codes (keys) of the .DS_Store format — filtered from the strings scan
# so structural tokens don't masquerade as filenames. Known-set filter: an UNCOMMON type
# code can still leak through (accepted lossiness — see module docstring).
DSSTORE_TYPECODES = frozenset("""
    Iloc bwsp lsvp lsvP lsvo lsvC icvp vstl vSrn pBB0 pBBk pBB_ pbb0 pbbk ptbL ptbN
    moDD dscl dilf cboo fdsc icsp vvp bvpv alsW GRP0 cmmt extn clip cptb dutc logS
    modD ph1S ph2S phys pixv ptype
""".split())

GIT_URL_RE = re.compile(r"^\s*url\s*=\s*(\S+)\s*$", re.MULTILINE)
# https://user:password@host/... — the credential-bearing remote-URL shape.
CRED_URL_RE = re.compile(
    r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^/:@\s]+):(?P<pw>[^@\s/]+)@(?P<rest>\S+)$")
HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
ENV_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*\s*=", re.MULTILINE)
REFLOG_LINE_RE = re.compile(r"^[0-9a-fA-F]{40} [0-9a-fA-F]{40} .+\t")

PATH_VARIANTS = {
    "/.git/HEAD": "git_head", "/.git/config": "git_config", "/.git/logs/HEAD": "git_reflog",
    "/.svn/wc.db": "svn_wcdb", "/.svn/entries": "svn_entries",
    "/.hg/requires": "hg_requires", "/.bzr/branch-format": "bzr_branch_format",
    "/.DS_Store": "ds_store", "/.env": "env_file", "/.env.production": "env_file",
    "/web.config": "iis_config", "/connectionStrings.config": "iis_config",
    "/WEB-INF/web.xml": "java_web_xml", "/application.properties": "spring_properties",
    "/config.php.bak": "php_source_bak", "/wp-config.php": "php_config",
    "/appsettings.json": "json_config", "/secrets.json": "json_config",
    "/backup.zip": "backup_archive",
}

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PATTERN_TIER_RANK = {"high": 0, "medium": 1, "low": 2}


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# pure helpers (unit-tested directly — no HTTP anywhere near these)
# --------------------------------------------------------------------------

def parse_host(target: str) -> str | None:
    """'host' / 'host:8443' / 'https://host/path' -> scheme://netloc origin, or None.
    Bare hosts get https:// (cors_check.parse_target precedent); any path on the input
    is dropped — this sweep probes a fixed absolute path list from the origin root."""
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    p = urllib.parse.urlsplit(t)
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}"


def looks_genuine(path: str, text: str, data: bytes) -> str | None:
    """§4d ladder's info/low boundary: return a short reason string when the 200 body is
    genuinely the expected file type for this path (-> low), else None (bare 200 -> info).
    Best-effort format fingerprints — strong enough that a catch-all index.html cannot
    satisfy any of them (no 'ref: refs/', no SQLite magic, no '<?php' in SPA shells)."""
    t = text.strip()
    if path == "/.git/HEAD":
        if t.startswith("ref: refs/"):
            return "body starts with 'ref: refs/' — genuine git HEAD"
        if HEX40_RE.fullmatch(t):
            return "body is a bare 40-hex SHA — genuine detached-HEAD git HEAD"
        return None
    if path == "/.git/config":
        if "[core]" in text and "repositoryformatversion" in text:
            return "git-config structure present ([core] + repositoryformatversion)"
        return None
    if path == "/.git/logs/HEAD":
        lines = text.splitlines()
        if lines and REFLOG_LINE_RE.match(lines[0]):
            return "reflog line format (<old> <new> <ident>\\t<action>) — genuine git reflog"
        return None
    if path == "/.svn/wc.db":
        if data.startswith(b"SQLite format 3\x00"):
            return "SQLite magic header — genuine SQLite db (svn 1.7+ wc.db)"
        return None
    if path == "/.svn/entries":
        lines = text.splitlines()
        if lines and (lines[0].strip().isdigit() or lines[0].strip() == "dir"):
            return "svn <=1.6 entries format (leading version digit / 'dir') — genuine"
        return None
    if path == "/.hg/requires":
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if lines and all(re.fullmatch(r"[a-z0-9_.-]+", l) for l in lines):
            return "bare store-requirement tokens (revlogv1/store/...) — genuine hg requires"
        return None
    if path == "/.bzr/branch-format":
        if t.startswith("Bazaar-NG branch, format"):
            return "'Bazaar-NG branch, format' header — genuine bzr branch-format"
        return None
    if path == "/.DS_Store":
        if data.startswith(DSSTORE_MAGIC):
            return "Bud1 magic header — genuine .DS_Store"
        return None
    if path in ("/.env", "/.env.production", "/application.properties"):
        kv = ENV_LINE_RE.findall(text)
        if len(kv) >= 2 and not HTMLISH_RE.search(text[:256]):
            return "%d KEY=VALUE-style line(s), not HTML — genuine config-style file" % len(kv)
        return None
    if path == "/web.config":
        low = text.lower()
        if "<configuration" in low and "<system.web" in low:
            return "IIS configuration structure (<configuration> + <system.web>) — genuine"
        return None
    if path == "/connectionStrings.config":
        low = text.lower()
        if "<connectionstrings" in low or "connectionstring=" in low:
            return "connectionStrings XML structure — genuine"
        return None
    if path == "/WEB-INF/web.xml":
        if "<web-app" in text.lower():
            return "<web-app> descriptor element — genuine web.xml"
        return None
    if path == "/config.php.bak":
        if "<?php" in text:
            return "PHP source (<?php) — genuine PHP file"
        return None
    if path == "/wp-config.php":
        if "<?php" in text and ("DB_NAME" in text or "table_prefix" in text
                                or "wp-settings" in text):
            return "PHP source with WordPress config markers — genuine wp-config.php"
        return None
    if path in ("/appsettings.json", "/secrets.json"):
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        if isinstance(parsed, dict):
            return "parses as a JSON object — genuine JSON config"
        return None
    if path == "/backup.zip":
        if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            return "ZIP magic (PK header) — genuine zip archive"
        return None
    return None


def secret_scan(text: str) -> dict:
    """TWO separate signals, never merged (see module docstring): (1) the js-analysis.md §2
    SECRET_PATTERNS set via js_recon.mine_text (kind/tier/line/context travel along);
    (2) recon.md §4d's own broader catch-all phrase grep, deduped and bounded — evidence,
    not a reimplementation of the file."""
    mined = mine_text(text)
    phrases: list[dict] = []
    seen: set[str] = set()
    for m in SECRET_PHRASE_RE.finditer(text):
        p = m.group(0).lower()
        if p in seen:
            continue
        seen.add(p)
        phrases.append({"phrase": p, "line": text.count("\n", 0, m.start()) + 1})
        if len(phrases) >= 16:
            break
    return {"pattern_hits": mined["secrets"], "phrase_hits": phrases,
            "html_body": bool(HTMLISH_RE.search(text[:256]))}


def extract_dsstore_names(data: bytes) -> list[str]:
    """BEST-EFFORT, LOSSY filename extraction from a .DS_Store blob (see module docstring
    for why no real parser: zero-pip-deps rule). strings(1)-style printable-ASCII runs,
    plus UTF-16BE-shaped runs — the format stores names as UTF-16BE, so ASCII text sits
    in the blob as b'\\x00d\\x00a\\x00t...', which a plain strings pass reads as junk —
    with the magic and known 4-char record type codes filtered. Positional order,
    deduped — deterministic."""
    names: list[str] = []
    seen: set[str] = set()

    def add(s: str) -> None:
        if s == "Bud1" or s in DSSTORE_TYPECODES or s in seen:
            return
        seen.add(s)
        names.append(s)

    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        add(m.group(0).decode("ascii", "replace"))
    for m in re.finditer(rb"(?:\x00[\x20-\x7e]){4,}", data):  # UTF-16BE: NUL BEFORE each char
        add(m.group(0).decode("utf-16-be", "replace"))
    return names


def redact_remote(url: str) -> tuple[str, bool]:
    """('https://user:pass@host/x', ...) -> ('https://user:<redacted:N-chars>@host/x', True).
    The password is NEVER echoed into evidence (findings discipline: no secrets in
    findings/) — the redacted form proves the structure; next_action says where the full
    URL lives (in the recovered file itself)."""
    m = CRED_URL_RE.match(url)
    if m is None:
        return url, False
    return ("%s%s:<redacted:%d-chars>@%s"
            % (m.group("scheme"), m.group("user"), len(m.group("pw")), m.group("rest"))), True


def extract_git_remotes(config_text: str) -> list[dict]:
    """All `url = <value>` lines of a git config (§4d(b): the origin remote sometimes
    reveals an internal git host — or embedded credentials, which are their own finding)."""
    out = []
    for m in GIT_URL_RE.finditer(config_text):
        redacted, credentialed = redact_remote(m.group(1))
        out.append({"url": m.group(1), "redacted": redacted, "credentialed": credentialed})
    return out


def _sample(data: bytes, width: int = 2048) -> str:
    """Whitespace-normalized head-of-body sample for the catch-all/soft-200 comparison."""
    return " ".join(data[:width].decode("utf-8", "replace").split())


# --------------------------------------------------------------------------
# next_action language — the §4d ladder lives here (deeper reconstruction is explicitly
# delegated to the doc's own tools; this script is a detector, not git-dumper)
# --------------------------------------------------------------------------

VENDORED_CAVEAT = ("'low' means a real source/config file was recovered — NOT that this is "
                   "definitely sensitive app logic: vendored framework code with no "
                   "secrets/app-logic is Info at best (recon.md §4d caveat)")

BARE_200_NEXT = ("open the URL manually (curl/browser) and read the body — a bare 200 is "
                 "Info per the recon.md §4d ladder, and catch-all/soft-200 servers fake "
                 "these hits; only a genuinely-formatted file escalates to low")

GIT_NEXT = ("reconstruct the repo with git-dumper (recon.md §4d): git-dumper <this URL's "
            "origin>/.git/ /tmp/dump && git log --all --oneline && git log -p --all | "
            "grep -iE 'password|secret|api[_-]?key|aws|jdbc|connectionstring|begin .*private "
            "key' — repo reconstruction is out of scope for this detector. " + VENDORED_CAVEAT)

SVN_NEXT = ("pull and query the wc.db (recon.md §4d): curl -s <this URL> -o /tmp/wc.db && "
            "sqlite3 /tmp/wc.db \"SELECT local_relpath, checksum FROM NODES;\" — pristine "
            "objects at /.svn/pristine/<2-char>/<sha1>.svn-base (svn <=1.6: /.svn/entries + "
            "/.svn/text-base/*.svn-base). " + VENDORED_CAVEAT)

HG_NEXT = ("confirm the fingerprint then dump with dvcs-ripper (recon.md §4d): rip-hg.pl -v "
           "-u <this URL's origin>/.hg/ — reconstruction out of scope for this detector. "
           + VENDORED_CAVEAT)

BZR_NEXT = ("confirm the fingerprint then dump with dvcs-ripper (recon.md §4d): rip-bzr.pl "
            "-v -u <this URL's origin>/.bzr/ — reconstruction out of scope for this "
            "detector. " + VENDORED_CAVEAT)

DSSTORE_NEXT = ("fetch the leaked filenames manually and grep them: grep -rilE "
                "'backup|admin|config|\\.sql|\\.zip|\\.bak|internal|test' (recon.md §4d); "
                "for the full recursive map run ds_store_exp.py / pip ds_store manually — "
                "this script's extraction is a best-effort/lossy strings-style scan, not a "
                "parser")

ENVCFG_NEXT = ("read the recovered file and pull the live-looking values (recon.md §4d "
               "stack table: DB_PASSWORD/APP_KEY/AWS_*/STRIPE_*, conn strings, machineKey, "
               "datasource creds); verify any hit live per validate.md before reporting. "
               + VENDORED_CAVEAT)

BACKUP_NEXT = ("download and unzip -l — archive contents are out of scope for this "
               "detector's sweep; grep the extracted tree for secrets/sinks. " + VENDORED_CAVEAT)

PATTERN_NEXT = ("regex match only, NOT verified live — validate.md gate: confirm the "
                "credential is live and unrestricted before reporting (it may equally be a "
                "bundled example/placeholder); the recon.md §4d ladder tops out at High "
                "for this technique")

PHRASE_NEXT = ("generic secret-indicator phrase only (recon.md §4d catch-all grep: "
               "password|secret|api[_-]?key|aws|jdbc|connectionstring|begin .*private key) "
               "— NOT a verified secret pattern, so severity stays at the file's base "
               "level: open the recovered file, identify the actual value, and validate "
               "live per validate.md before treating this as High")

REMOTE_CREDS_NEXT = ("embedded plaintext credential in a git remote URL — categorically "
                     "worse than a regex-shaped match because user:pass@ is a complete, "
                     "directly-usable credential string, not half of one. Still high, not "
                     "critical: creds in abandoned configs are routinely stale/rotated. "
                     "validate.md gate: open the recovered /.git/config for the full URL "
                     "(password redacted here per findings discipline) and test the "
                     "credential only against YOUR OWN authorized access")

# js_recon kind-tier notes, for evidence (kind -> note text from SECRET_PATTERNS)
PATTERN_TIER_NOTES = {kind: note for kind, _, _, note in SECRET_PATTERNS}


# --------------------------------------------------------------------------
# the pipeline
# --------------------------------------------------------------------------

def sweep_host(origin: str, timeout: float, verbose: bool = False) -> dict:
    """One host: tier-1 + tier-2 bounded GETs, §4d-ladder evaluation of every 200, git
    origin-remote extraction, .DS_Store filename extraction. Never raises: any unexpected
    error degrades into this host's error entry (one bad host must never kill a batch)."""
    evidence: list[str] = []
    errors: list[str] = []
    findings: list[dict] = []
    stats = {"host": origin, "paths_tried": 0, "hits": 0, "misses": 0, "fetch_errors": 0,
             "tier1_hits": 0, "tier2_hits": 0, "requests": 1, "catch_all_suspect": False,
             "error": None}

    def ev(msg: str) -> None:
        evidence.append("%s: %s" % (origin, msg))
        if verbose:
            eprint("  [%s] %s" % (origin, msg))

    try:
        # ---- catch-all tripwire: one root GET, used ONLY for honest annotation -------
        root = http_fetch(origin + "/", timeout, max_bytes=ROOT_PROBE_BYTES,
                          extra_headers={"User-Agent": USER_AGENT})
        root_sample = ""
        if root["error"] is None and root["status"] == 200 and not root["over_cap"]:
            root_sample = _sample(root["body"] or b"")
        elif root["error"] is not None and verbose:
            ev("root probe failed (%s) — catch-all comparison unavailable" % root["error"])

        # ---- tier 1 + tier 2: one bounded GET per path ------------------------------
        hits: list[dict] = []
        failed: list[tuple[str, str]] = []
        for tier, path in ALL_PATHS:
            stats["paths_tried"] += 1
            r = http_fetch(origin + path, timeout, max_bytes=MAX_BODY_BYTES,
                           extra_headers={"User-Agent": USER_AGENT})
            stats["requests"] += 1
            if r["error"] is not None:
                failed.append((path, r["error"]))
                continue
            if r["status"] == 200:
                data = r["body"] or b""
                hits.append({"tier": tier, "path": path, "url": origin + path,
                             "data": data, "over_cap": r["over_cap"],
                             "redirects": r["redirects"], "final_url": r["final_url"],
                             "sample": _sample(data)})
            else:
                stats["misses"] += 1   # counted, never enumerated — misses flood output
        stats["hits"] = len(hits)

        if failed:
            stats["fetch_errors"] = len(failed)
            if len(failed) == stats["paths_tried"]:
                # dead host: one collapsed line, not 19 identical errors
                errors.append("%s: all %d disclosure-path probe(s) failed at transport "
                              "level (%s) — host unreachable this run"
                              % (origin, len(failed), failed[0][1]))
            else:
                errors.extend("%s%s: FETCH_FAILED — %s" % (origin, p, e) for p, e in failed)

        # repeat-body detection across this host's hits (catch-all tell #2)
        sample_counts: dict[str, int] = {}
        for h in hits:
            sample_counts[h["sample"]] = sample_counts.get(h["sample"], 0) + 1

        # ---- evaluate every hit on the §4d ladder -----------------------------------
        by_path: dict[str, dict] = {}
        for h in hits:
            catch_note = False
            stats["tier%s_hits" % h["tier"][-1]] += 1
            text = h["data"].decode("utf-8", "replace")
            genuine = looks_genuine(h["path"], text, h["data"])
            scan = secret_scan(text)
            severity = "low" if genuine else "info"
            confidence = CONF_GENUINE if genuine else CONF_BARE_200

            ev_lines = ["HIT 200 %s (%s)" % (h["url"], h["tier"])]
            if h["redirects"]:
                ev_lines.append("200 reached only after %d redirect(s) (final: %s) — "
                                "redirect-to-generic-page 200s are a classic false HIT, "
                                "verify the body is really this path's file"
                                % (len(h["redirects"]), h["final_url"]))
            if genuine:
                ev_lines.append("genuine file recovered: %s" % genuine)
            else:
                ev_lines.append("200 but the body does NOT match the expected format for "
                                "this path — bare-200 hit, Info per the recon.md §4d ladder "
                                "(soft-200/catch-all servers fake these)")
            if h["over_cap"]:
                ev_lines.append("body capped at %d bytes — content beyond the cap was NOT "
                                "swept for secrets (fetch manually to examine fully)"
                                % MAX_BODY_BYTES)

            # signal 1: SECRET_PATTERNS (escalates per §4d; low-tier kinds only annotate)
            pattern_hits = scan["pattern_hits"]
            best = None
            if pattern_hits:
                best = min(pattern_hits, key=lambda p: PATTERN_TIER_RANK[p["tier"]])
                ev_lines.append("SECRET_PATTERNS hit(s): %d (showing up to 5)"
                                % len(pattern_hits))
                for p in pattern_hits[:5]:
                    ev_lines.append("  kind=%s tier=%s line=%d match=%s"
                                    % (p["kind"], p["tier"], p["line"], p["match"]))
                if len(pattern_hits) > 5:
                    ev_lines.append("  ... %d more match(es) in the recovered body"
                                    % (len(pattern_hits) - 5))
                ev_lines.append("tier rationale: %s" % PATTERN_TIER_NOTES.get(
                    best["kind"], "(kind note unavailable)"))
                if best["tier"] in ("high", "medium"):
                    severity, confidence = "high", CONF_PATTERN_TIER[best["tier"]]
                    ev_lines.append("regex pattern match only — NOT verified live; the "
                                    "matched value may be restricted, rotated, or a "
                                    "placeholder/example")
                else:
                    ev_lines.append("low-confidence pattern kind only (often "
                                    "public-by-design) — annotates, does not escalate")

            # signal 2: the doc's catch-all phrase grep (recorded, never escalating alone)
            phrase_hits = scan["phrase_hits"]
            if phrase_hits:
                if scan["html_body"]:
                    ev_lines.append("catch-all phrase signal SUPPRESSED: body looks like "
                                    "an HTML page, where words like 'password' are "
                                    "expected (login forms); SECRET_PATTERNS still ran")
                else:
                    joined = ", ".join("%s (line %d)" % (p["phrase"], p["line"])
                                       for p in phrase_hits)
                    ev_lines.append("catch-all indicator phrase(s) per recon.md §4d grep: %s"
                                    % joined)
                    if best is None or best["tier"] == "low":
                        confidence = CONF_PHRASE
                        if not genuine:
                            ev_lines.append("phrase-only signal on an unconfirmed body — "
                                            "lowest-confidence combination this tool emits")

            # catch-all annotation (recon.md §6) — honesty note, never a severity change
            if root_sample and h["sample"] == root_sample:
                stats["catch_all_suspect"] = catch_note = True
                ev_lines.append("body identical to the site root page — likely a "
                                "catch-all/soft-200 (recon.md §6): treat this hit as "
                                "UNCONFIRMED")
            elif sample_counts[h["sample"]] >= 3:
                stats["catch_all_suspect"] = catch_note = True
                ev_lines.append("identical body served at %d of this host's probed paths "
                                "this run — likely a catch-all/soft-200 (recon.md §6)"
                                % sample_counts[h["sample"]])

            if genuine:
                ev_lines.append(VENDORED_CAVEAT)

            next_action = BARE_200_NEXT
            if severity == "high":
                next_action = PATTERN_NEXT
            elif genuine:
                next_action = {
                    "git": GIT_NEXT, "svn": SVN_NEXT, "hg": HG_NEXT, "bzr": BZR_NEXT,
                    "ds_store": DSSTORE_NEXT, "env": ENVCFG_NEXT, "backup": BACKUP_NEXT,
                }[{
                    "git_head": "git", "git_config": "git", "git_reflog": "git",
                    "svn_wcdb": "svn", "svn_entries": "svn", "hg_requires": "hg",
                    "bzr_branch_format": "bzr", "ds_store": "ds_store",
                    "env_file": "env", "iis_config": "env", "java_web_xml": "env",
                    "spring_properties": "env", "php_source_bak": "env",
                    "php_config": "env", "json_config": "env",
                    "backup_archive": "backup",
                }[PATH_VARIANTS[h["path"]]]]
            elif phrase_hits and not scan["html_body"]:
                next_action = PHRASE_NEXT

            finding = {"type": "source_disclosure", "severity": severity,
                       "confidence": confidence, "target": h["url"],
                       "variant": PATH_VARIANTS[h["path"]], "path": h["path"],
                       "tier": h["tier"], "evidence": ev_lines, "source": SOURCE,
                       "next_action": next_action}
            findings.append(finding)
            # raw bytes kept alongside: the decoded text is lossy ("replace") and the
            # .DS_Store extractor must run over the true bytes, not replacements
            by_path[h["path"]] = {"finding": finding, "text": text, "data": h["data"]}
            # compact mirror into the run log: one line per hit (full detail lives in the
            # finding's own evidence — misses stay unenumerated, hits stay bounded)
            mirror = "HIT 200 %s (%s) -> %s/%s conf %.2f" % (
                h["url"], h["tier"], severity.upper(), PATH_VARIANTS[h["path"]], confidence)
            if severity == "high" and best is not None:
                mirror += " — secret pattern: kind=%s match=%s" % (best["kind"], best["match"])
            if catch_note:
                mirror += " — CATCH-ALL SUSPECT (recon.md §6)"
            ev(mirror)

        # ---- §4d(b): /.git/HEAD -> origin-remote extraction from /.git/config --------
        if "/.git/HEAD" in by_path:
            head_entry = by_path["/.git/HEAD"]
            cfg_entry = by_path.get("/.git/config")
            cfg_text = cfg_entry["text"] if cfg_entry else None
            if cfg_entry is None:
                # §4d(b): "ALSO fetch /.git/config (if not already a separate hit)" —
                # covers a transient tier-1 miss; a real 404 just misses again, once.
                r = http_fetch(origin + "/.git/config", timeout, max_bytes=MAX_BODY_BYTES,
                               extra_headers={"User-Agent": USER_AGENT})
                stats["requests"] += 1
                if r["error"] is None and r["status"] == 200:
                    cfg_text = (r["body"] or b"").decode("utf-8", "replace")
                    ev("auxiliary fetch of /.git/config succeeded on retry (tier-1 probe "
                       "missed) — remote extraction below")
            if cfg_text is not None:
                remotes = extract_git_remotes(cfg_text)
                if not remotes:
                    head_entry["finding"]["evidence"].append(
                        "origin remote undetermined: no 'url =' line in the recovered "
                        "/.git/config")
                for remote in remotes:
                    attach = (cfg_entry["finding"]["evidence"] if cfg_entry else
                              head_entry["finding"]["evidence"])
                    if remote["credentialed"]:
                        # distinct high finding — see CONF_REMOTE_CREDS for the
                        # high-not-critical reasoning
                        findings.append({
                            "type": "source_disclosure", "severity": "high",
                            "confidence": CONF_REMOTE_CREDS,
                            "target": origin + "/.git/config",
                            "variant": "git_remote_credential", "path": "/.git/config",
                            "tier": "tier 1",
                            "evidence": [
                                "credential-bearing git remote URL in the recovered "
                                "/.git/config: %s" % remote["redacted"],
                                "password present in the file but redacted in this "
                                "evidence per findings discipline (no secrets in "
                                "findings/) — the full URL is in the recovered file",
                                "user:pass@ in a remote URL is a complete, "
                                "directly-usable credential string, not a regex-shaped "
                                "half-credential — hence its own finding, still high "
                                "pending the validate.md live gate",
                            ],
                            "source": SOURCE, "next_action": REMOTE_CREDS_NEXT})
                        ev("git remote with EMBEDDED CREDENTIALS found (%s) — distinct "
                           "high finding emitted" % remote["redacted"])
                    else:
                        attach.append("git remote URL: %s — reveals the git provider/"
                                      "internal host" % remote["redacted"])
                        ev("git remote: %s" % remote["redacted"])
            else:
                head_entry["finding"]["evidence"].append(
                    "origin remote undetermined: /.git/config not retrievable this run")

        # ---- §4d(c): /.DS_Store best-effort filename extraction ----------------------
        if "/.DS_Store" in by_path:
            ds_finding = by_path["/.DS_Store"]["finding"]
            names = extract_dsstore_names(by_path["/.DS_Store"]["data"])
            if names:
                ev(".DS_Store filename-ish strings extracted (best-effort/lossy): %s"
                   % ", ".join(names[:20]))
                shown = names[:40]
                ds_finding["evidence"].append(
                    "filename-ish strings extracted (BEST-EFFORT/LOSSY strings-style "
                    "scan, not a .DS_Store parser — zero-pip-deps constraint): %s%s"
                    % (", ".join(shown),
                       " … (+%d more)" % (len(names) - 40) if len(names) > 40 else ""))
                interesting = [n for n in names if DSSTORE_INTEREST_RE.search(n)]
                if interesting:
                    ds_finding["evidence"].append(
                        "matches the recon.md §4d interesting-filename grep "
                        "(backup|admin|config|.sql|.zip|.bak|internal|test): %s"
                        % ", ".join(interesting[:20]))
            else:
                ds_finding["evidence"].append(
                    "no filename-looking strings extracted (the best-effort strings-style "
                    "scan is lossy by design — run ds_store_exp.py manually for a full parse)")
    except Exception as e:  # never let one host kill the batch
        stats["error"] = "unexpected error: %s: %s" % (type(e).__name__, e)
        errors.append("%s: %s" % (origin, stats["error"]))

    return {"stats": stats, "findings": findings, "evidence": evidence, "errors": errors}


def scan_hosts(hosts: list[str], timeout: float = DEFAULT_TIMEOUT,
               threads: int = DEFAULT_THREADS, verbose: bool = False) -> dict:
    """Full batch pipeline; returns ONE normalized result object for the whole batch
    (aggregated findings + per-host stats in metadata), whatever the batch size."""
    # dedupe, preserve order (recon/live.txt lists are anew'd but never trusted)
    seen: set = set()
    hosts = [h for h in hosts if not (h in seen or seen.add(h))]
    parsed: list[str] = []
    invalid: list[str] = []
    for h in hosts:
        origin = parse_host(h)
        if origin is None:
            invalid.append(h)
        elif origin not in parsed:
            parsed.append(origin)
    target_label = parsed[0] if len(parsed) == 1 else "batch:%d hosts" % len(parsed)

    def run_one(origin: str) -> dict:
        return sweep_host(origin, timeout, verbose)

    if len(parsed) <= 1:
        results = [run_one(parsed[0])] if parsed else []
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, len(parsed))) as pool:
            futures = {pool.submit(run_one, o): o for o in parsed}
            by_origin = {}
            for fut in concurrent.futures.as_completed(futures):
                by_origin[futures[fut]] = fut.result()
            results = [by_origin[o] for o in parsed]  # preserve input order

    evidence: list[str] = []
    errors: list[str] = ["%s: invalid host/URL — skipped" % h for h in invalid]
    findings: list[dict] = []
    host_stats: list[dict] = [{"host": h, "paths_tried": 0, "hits": 0, "misses": 0,
                               "fetch_errors": 0, "tier1_hits": 0, "tier2_hits": 0,
                               "requests": 0, "catch_all_suspect": False,
                               "error": "invalid host/URL — skipped"} for h in invalid]
    totals = {"hosts": len(parsed), "paths_tried": 0, "hits": 0, "misses": 0,
              "fetch_errors": 0, "requests_made": 0}
    for res in results:
        evidence.extend(res["evidence"])
        errors.extend(res["errors"])
        findings.extend(res["findings"])
        s = res["stats"]
        host_stats.append(s)
        for key in ("paths_tried", "hits", "misses", "fetch_errors", "requests"):
            totals["requests_made" if key == "requests" else key] += s[key]

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

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
            "tier1_paths": list(TIER1_PATHS),
            "tier2_paths": list(TIER2_PATHS),
            "max_body_bytes": MAX_BODY_BYTES,
            "hosts": host_stats,
            "totals": {**totals, "findings_by_severity": by_severity},
        },
    }


# --------------------------------------------------------------------------
# CLI (conventions shared with cms_detect.py / js_recon.py / cors_check.py)
# --------------------------------------------------------------------------

def load_target_list(path: str) -> list[str]:
    """recon/live.txt format: one target per line; recon.md §4d's own loop reads $1
    (lines may carry an IP/extra columns), so the first whitespace token is taken.
    Blank lines and #-comments skipped."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"list file not found: {path}")
    out: list[str] = []
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        out.append(ln.split()[0])
    return out


def print_human(result: dict, quiet: bool) -> None:
    if quiet:
        return
    for h in result["metadata"]["hosts"]:
        eprint("[%s] %d path(s) tried: %d hit(s), %d miss(es), %d fetch error(s)%s" % (
            h["host"], h["paths_tried"], h["hits"], h["misses"], h["fetch_errors"],
            " — CATCH-ALL SUSPECT" if h["catch_all_suspect"] else ""))
    for f in result["findings"]:
        eprint("[%s] %s/%s (confidence %.2f) — %s" % (
            f["target"], f["severity"].upper(), f.get("variant", "source_disclosure"),
            f["confidence"], f["next_action"].split(". ")[0]))
    for err in result["errors"]:
        eprint("ERROR: %s" % err)
    totals = result["metadata"]["totals"]
    eprint("")
    eprint("totals: %d host(s), %d path(s) tried, %d hit(s), %d finding(s) %s" % (
        totals["hosts"], totals["paths_tried"], totals["hits"], len(result["findings"]),
        totals["findings_by_severity"] or "(all clean)"))
    eprint("")
    eprint("Next: for each low/high hit, follow the finding's next_action — reconstruct "
           "VCS dumps with the recon.md §4d tools (git-dumper / sqlite3 / dvcs-ripper) and "
           "validate any secret hit live per validate.md before reporting; a bare 200 is "
           "Info only, and record every swept host as tested-and-clean in coverage.md")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=SOURCE,
        description="Source/config disclosure sweeper (recon.md §4d): tier-1 triage sweep "
                    "(14 paths) + tier-2 env/config-by-stack (5 paths) across a "
                    "recon/live.txt-style host list, with genuine-file format checks, the "
                    "§4d severity ladder (200=info, real file=low, +secret pattern=high, "
                    "never critical), git origin-remote extraction (credentialed remote = "
                    "distinct high finding), and best-effort .DS_Store filename extraction. "
                    "A detector, not git-dumper — reconstruction is delegated via next_action.",
        epilog="examples:\n"
               "  %(prog)s https://host.example\n"
               "  %(prog)s -l recon/live.txt --json --output exposure.json\n"
               "  %(prog)s -l recon/live.txt --threads 20 --verbose\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hosts", nargs="*", metavar="host",
                    help="host(s)/URL(s) to sweep (bare hosts get https://; recon/live.txt "
                         "style — a leading IP/extra columns on -l lines is ignored)")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file of hosts, one per line, first whitespace token per line "
                         "(# comments allowed) — recon/live.txt format")
    ap.add_argument("--json", action="store_true",
                    help="machine output on stdout (normalized JSON; ONE object for the "
                         "whole batch)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SEC",
                    help="per-HTTP-operation timeout in seconds (default: 5)")
    ap.add_argument("--threads", type=int, default=DEFAULT_THREADS, metavar="N",
                    help="concurrent workers for the outer loop over hosts (default: 10; "
                         "each host's path sweep stays sequential)")
    ap.add_argument("--output", metavar="FILE",
                    help="also write the JSON result to this file")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress the human-readable summary (no effect with --json)")
    ap.add_argument("--verbose", action="store_true",
                    help="print each host's pipeline evidence to stderr as it runs")
    args = ap.parse_args(argv)

    hosts: list[str] = list(args.hosts)
    if args.list:
        try:
            hosts.extend(load_target_list(args.list))
        except (OSError, FileNotFoundError) as e:
            eprint(f"[!] {e}")
            return 2
    hosts = [h for h in (h.strip() for h in hosts) if h]
    if not hosts:
        ap.error("no hosts given (positional args or -l/--list FILE)")
    if args.timeout <= 0:
        ap.error("--timeout must be > 0")
    if args.threads < 1:
        ap.error("--threads must be >= 1")

    if not args.quiet and not args.json:
        eprint("[*] %s: %d host(s) | tier-1 paths: %d | tier-2 paths: %d | body cap: %dKB "
               "| timeout: %ss | pure stdlib HTTP" % (
                   TOOL, len(hosts), len(TIER1_PATHS), len(TIER2_PATHS),
                   MAX_BODY_BYTES // 1024, args.timeout))

    result = scan_hosts(hosts, timeout=args.timeout, threads=args.threads,
                        verbose=args.verbose)

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

    return 0  # completed scan — exit non-zero only for hard errors above


if __name__ == "__main__":
    sys.exit(main())
