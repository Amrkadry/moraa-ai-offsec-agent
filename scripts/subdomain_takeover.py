#!/usr/bin/env python3
"""subdomain_takeover.py — dangling-DNS / subdomain-takeover candidate detector (zero pip deps).

WHY: recon.md hands off hundreds of candidate subdomains; a dangling CNAME/NS pointing at an
unclaimed third-party service (GitHub Pages, S3, Heroku, ...) is one of the highest-value
findings in bug bounty — but the false-positive rate of "CNAME exists = takeover" is notorious
(see subdomain-takeover.md §3). This script never treats a bare CNAME as a finding. It runs a
7-stage pipeline and only escalates when INDEPENDENT signals agree:

    INPUT DOMAIN -> DNS LOOKUP -> CNAME DETECTION -> TARGET SERVICE IDENTIFICATION ->
    FINGERPRINT MATCH -> DNS STATE ANALYSIS -> SERVICE RESPONSE ANALYSIS -> CONFIDENCE -> RESULT

  1. DNS LOOKUP      dig +short CNAME (chain-followed, subprocess list args, never shell=True)
                     + dig +short NS for the NS-delegation variant (best-effort, see below).
  2. CNAME DETECTION no CNAME -> NOT_VULNERABLE (no dangling-CNAME vector; short-circuit).
  3. SERVICE ID      CNAME target matched against scripts/data/takeover_fingerprints.json
                     (regex patterns, data sourced from the public EdOverflow/can-i-take-over-xyz
                     dataset and Project Discovery nuclei takeover templates).
  4. FINGERPRINT     no pattern match -> INCONCLUSIVE (NOT "safe" — DB coverage is finite).
  5. DNS STATE       for services where the vulnerable state is a dead name (nxdomain_expected
                     true): dig the CNAME target itself. NXDOMAIN there = dangling. If the
                     target still resolves on such a service, it is likely claimed -> NOT_VULNERABLE.
                     A parent-wildcard control query (random label) downgrades DNS-only signals
                     — wildcard catch-alls synthesize CNAMEs that were never registered (the
                     acme.example r23 lesson in scripts/README.md).
  6. HTTP ANALYSIS   bounded HTTPS-then-HTTP GET (urllib, 5s default timeout, 64KB body cap,
                     TLS verification off — engagement boxes run intercepting proxies, same as
                     favicon_hash.py). 4xx/5xx/3xx are HTTP responses (bodies inspected, not
                     crashes); connection failures are evidence, never a positive signal.
  7. CONFIDENCE      POTENTIAL (0.40, pattern alone) < LIKELY (0.70, + dangling DNS state) <
                     CONFIRMED (0.90, + HTTP body fingerprint). No single weak signal may
                     produce CONFIRMED. No CNAME -> NOT_VULNERABLE 0.95 (strong negative).
                     "critical" is never auto-assigned: per subdomain-takeover.md §6 the jump
                     to critical comes from shared blast radius (cookie scope / CSP / OAuth
                     redirect_uri / mail), which only a human can verify per engagement.

NS-delegation variant (partial, best-effort): if the name has no CNAME but carries NS records,
each listed nameserver is probed for SOA. If none answers, the delegation may point at a deleted
provider zone -> POTENTIAL, manual verification required (subdomain-takeover.md §4). This is NOT
a full NS-takeover check (no provider-zone registration probing).

Severity mapping: SAFE/NOT_VULNERABLE/INCONCLUSIVE -> info, POTENTIAL -> low, LIKELY -> medium,
CONFIRMED -> high (see CONFIDENCE block below for the numeric mapping).

Zero pip dependencies by design — `pip install` routinely fails under PEP-668 on sandboxed
engagement boxes (house precedent: scripts/favicon_hash.py). Python 3 stdlib + dig only.

Usage:
    python3 subdomain_takeover.py sub.target.com [more.domains ...]
    python3 subdomain_takeover.py -l recon/subs.txt --json --output takeovers.json
    python3 subdomain_takeover.py sub.target.com --verbose          # stage-by-stage to stderr

Exit code: 0 for a completed scan (any verdict), non-zero only for hard errors (bad args,
missing -l file).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import glob
import json
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOL = "subdomain_takeover"
SCRIPT_DIR = Path(__file__).resolve().parent
FINGERPRINTS_FILE = SCRIPT_DIR / "data" / "takeover_fingerprints.json"
SOURCE = "subdomain_takeover.py"

MAX_CHAIN_HOPS = 8          # guard against CNAME loops
MAX_BODY_BYTES = 64 * 1024  # fingerprint pages are tiny; never buffer a whole site
MAX_NS_PROBES = 4           # SOA probes per NS delegation set
USER_AGENT = "Mozilla/5.0 (compatible; moraa-takeover/1.0; authorized-scope-use-only)"

# Verdict -> (severity, default next_action). Severity ladder documented in the task contract:
# SAFE/NOT_VULNERABLE/INCONCLUSIVE -> info, POTENTIAL -> low, LIKELY -> medium, CONFIRMED -> high.
# "critical" is intentionally absent: bumping to critical requires the shared-trust analysis in
# subdomain-takeover.md §6 (cookies/CSP/OAuth/mail) that no DNS probe can do — do it by hand.
SEVERITY_BY_VERDICT = {
    "SAFE": "info",
    "NOT_VULNERABLE": "info",
    "INCONCLUSIVE": "info",
    "POTENTIAL": "low",
    "LIKELY": "medium",
    "CONFIRMED": "high",
}
NEXT_ACTION_BY_VERDICT = {
    "CONFIRMED": "claim the resource to prove control (one labelled proof page), release after "
                 "triage, then report — assess blast radius per subdomain-takeover.md §6",
    "LIKELY": "attempt to register/claim the resource at the provider to confirm before reporting "
              "(subdomain-takeover.md §3)",
    "POTENTIAL": "verify manually: provider claimability + HTTP fingerprint "
                 "(can-i-take-over-xyz / nuclei -tags takeover)",
    "INCONCLUSIVE": "manual review — fingerprint DB may not cover this provider "
                    "(dig chain + curl with Host header)",
    "NOT_VULNERABLE": "no dangling record, no further action",
    "SAFE": "no action",
}

# Numeric confidence per verdict. Comment-documented mapping from the implementation plan:
#   fingerprint pattern match alone        -> POTENTIAL 0.40
#   + confirmed dangling DNS state         -> LIKELY    0.70
#   + HTTP body fingerprint also matches   -> CONFIRMED 0.90
#   no CNAME (strong negative)             -> NOT_VULNERABLE 0.95
#   service appears claimed (resolves on an nxdomain-style service, or serves non-matching
#   content)                               -> NOT_VULNERABLE 0.70-0.80
#   dig failure / unknown service          -> INCONCLUSIVE 0.50
# Wildcard-parent caveat downgrades: LIKELY -> POTENTIAL (0.45), claimed->NOT_VULNERABLE becomes
# INCONCLUSIVE (0.50) — a wildcarded parent can synthesize CNAMEs that were never registered.
VERDICT_CONFIDENCE = {
    "SAFE": 0.95,
    "NOT_VULNERABLE": 0.95,
    "INCONCLUSIVE": 0.50,
    "POTENTIAL": 0.40,
    "LIKELY": 0.70,
    "CONFIRMED": 0.90,
}

# Mirrors scripts/lib/tools.sh's extra search dirs so bash and python tooling find the same
# binaries (a non-login shell often lacks ~/go/bin on PATH).
EXTRA_TOOL_DIRS = (
    "~/go/bin",
    "~/.local/go/bin",
    "~/.local/bin",
    "/usr/local/bin",
    "/usr/local/sbin",
)


class DigError(Exception):
    """dig missing, timed out, or failed — never fatal to the run, fatal to one domain's signal."""


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# tool discovery (python mirror of lib/tools.sh)
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
# DNS via dig (argument LIST only — never shell=True, never interpolated strings)
# --------------------------------------------------------------------------

def run_dig(dig_path: str, args: list[str], timeout: float):
    """Thin seam over subprocess for testability. Returns (rc, stdout, stderr).

    Raises subprocess.TimeoutExpired / OSError — callers go through dig_stdout().
    """
    cp = subprocess.run([dig_path] + list(args), capture_output=True, text=True,
                        timeout=max(2.0, float(timeout) + 2.0))
    return cp.returncode, cp.stdout, cp.stderr


def dig_stdout(dig_path: str, args: list[str], timeout: float, tolerate: bool = False) -> str:
    """Run dig, return stdout. tolerate=True swallows errors to "" (best-effort probes)."""
    try:
        rc, out, err = run_dig(dig_path, args, timeout)
    except subprocess.TimeoutExpired:
        if tolerate:
            return ""
        raise DigError(f"dig timed out after {timeout}s ({' '.join(args)})") from None
    except OSError as e:
        if tolerate:
            return ""
        raise DigError(f"dig failed to run: {e}") from None
    if rc != 0:
        # A resolver communication failure (e.g. rc=9 "no servers could be reached") prints
        # dig's own ";; ..." diagnostic to STDOUT under +short, not just stderr — treating
        # "rc != 0 and stdout is empty" as the error condition let that diagnostic text slip
        # through as if it were real record data (seen live: a transient WSL NAT-resolver
        # hiccup turned "no NS answered" into a fabricated NS entry reading the error message
        # itself, producing a false POTENTIAL takeover verdict). Any nonzero rc is a dig
        # failure, full stop — legitimate empty/NXDOMAIN answers under +short always come
        # back rc=0.
        if tolerate:
            return ""
        detail = (out or err or "").strip()[:160]
        raise DigError(f"dig rc={rc}: {detail}")
    return out


def dig_short(dig_path: str, qname: str, rtype: str, timeout: float) -> list[str]:
    t = str(int(max(1, timeout)))
    out = dig_stdout(dig_path, ["+time=" + t, "+tries=1", "+short", rtype, qname], timeout)
    return [ln.strip().rstrip(".").lower() for ln in out.splitlines() if ln.strip()]


def dig_status(dig_path: str, qname: str, timeout: float) -> str:
    """Return the header status (NOERROR/NXDOMAIN/SERVVAIL/...) for an A query on qname."""
    t = str(int(max(1, timeout)))
    out = dig_stdout(dig_path, ["+time=" + t, "+tries=1", "+noall", "+comments", qname], timeout)
    m = re.search(r"status:\s*([A-Z]+)", out)
    return m.group(1) if m else "UNKNOWN"


def resolve_cname_chain(dig_path: str, domain: str, timeout: float) -> list[str]:
    """Follow the CNAME chain hop by hop (dig +short CNAME only ever shows one hop).
    Returns [input, hop1, hop2, ...]; single-element list = no CNAME at the input."""
    chain = [domain]
    cur = domain.lower()
    for _ in range(MAX_CHAIN_HOPS):
        outs = dig_short(dig_path, cur, "CNAME", timeout)
        if not outs:
            break
        nxt = outs[0]
        if nxt == cur or nxt in chain:  # loop guard
            chain.append(nxt)
            break
        chain.append(nxt)
        cur = nxt
    return chain


def check_target_resolves(dig_path: str, target: str, timeout: float) -> bool | None:
    """True (resolves) / False (NXDOMAIN) / None (unknown — SERVFAIL, timeout, ...)."""
    if dig_short(dig_path, target, "A", timeout):
        return True
    status = dig_status(dig_path, target, timeout)
    if status == "NXDOMAIN":
        return False
    if status == "NOERROR":
        return True  # name exists (other record types / chain through another CNAME)
    return None


def wildcard_parent_detected(dig_path: str, domain: str, timeout: float) -> tuple[bool, str]:
    """Control probe: does a random never-registered label under the parent zone resolve?
    If yes, the parent wildcards and ANY CNAME we saw may be wildcard-synthesized, not a
    registered record (dns_brute.sh's per-zone wildcard pre-flight, same rationale)."""
    labels = domain.split(".")
    if len(labels) < 3:
        return False, "skipped (apex/single-label name — a wildcard record cannot synthesize it)"
    parent = ".".join(labels[1:])
    probe = "moraadns-wildcard-" + uuid.uuid4().hex[:12] + "." + parent
    try:
        cnames = dig_short(dig_path, probe, "CNAME", timeout)
        if cnames:
            return True, f"random label {probe} -> CNAME {cnames[0]}"
        ips = dig_short(dig_path, probe, "A", timeout)
        if ips:
            return True, f"random label {probe} -> A {ips[0]}"
        return False, f"control label {probe} is NXDOMAIN (no wildcard)"
    except DigError as e:
        return False, f"control query failed ({e}) — wildcard caveat unavailable"


# --------------------------------------------------------------------------
# HTTP probe (stdlib urllib — no requests, redirects NOT followed so 3xx is visible)
# --------------------------------------------------------------------------

def _build_opener() -> urllib.request.OpenerDirector:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # engagement boxes run intercepting proxies (favicon_hash.py precedent)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # surfaces 3xx as HTTPError so we can see Location

    return urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))


_OPENER = _build_opener()


def probe_http(url: str, timeout: float) -> dict:
    """One GET. Returns {url, status, body, error}; 4xx/5xx/3xx are responses (error=None)."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "*/*",
                          "Accept-Encoding": "identity", "Connection": "close"})
        with _OPENER.open(req, timeout=timeout) as resp:
            return {"url": url, "status": resp.status,
                    "body": resp.read(MAX_BODY_BYTES).decode("utf-8", "replace"), "error": None}
    except urllib.error.HTTPError as e:  # 3xx (no-redirect opener), 4xx, 5xx — still a response
        try:
            body = e.read(MAX_BODY_BYTES).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"url": url, "status": e.code, "body": body, "error": None}
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as e:
        return {"url": url, "status": None, "body": None, "error": f"{type(e).__name__}: {e}"}


# --------------------------------------------------------------------------
# fingerprint DB
# --------------------------------------------------------------------------

def load_fingerprints(path: Path = FINGERPRINTS_FILE) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array of fingerprint objects")
    return data


def match_service(target: str, fingerprints: list[dict]) -> dict | None:
    for fp in fingerprints:
        for pat in fp.get("cname_patterns", []):
            try:
                if re.search(pat, target, re.IGNORECASE):
                    return fp
            except re.error:
                continue  # a broken DB pattern must never take the scanner down
    return None


# --------------------------------------------------------------------------
# the pipeline
# --------------------------------------------------------------------------

def scan_domain(domain: str, fingerprints: list[dict], timeout: float = 5.0,
                dig_path: str | None = None, verbose: bool = False) -> dict:
    """Run the full pipeline for one domain; return the normalized result object."""
    evidence: list[str] = []
    errors: list[str] = []

    def ev(msg: str) -> None:
        evidence.append(msg)
        if verbose:
            eprint(f"  [{domain}] {msg}")

    def fail(verdict: str, reason: str, next_action: str | None = None,
             conf: float | None = None) -> dict:
        if conf is None:
            conf = VERDICT_CONFIDENCE[verdict]
        ev(f"verdict: {verdict} ({conf:.2f}) — {reason}")
        finding = {
            "type": "subdomain_takeover",
            "severity": SEVERITY_BY_VERDICT[verdict],
            "confidence": conf,
            "target": domain,
            "evidence": list(evidence),
            "source": SOURCE,
            "verdict": verdict,
            "next_action": next_action or NEXT_ACTION_BY_VERDICT[verdict],
        }
        return {
            "tool": TOOL,
            "target": domain,
            "timestamp": now_iso(),
            "status": "success",
            "findings": [finding],
            "evidence": list(evidence),
            "errors": list(errors),
            "metadata": {"timeout_s": timeout, "dig": dig_path,
                         "matched_service": (service or {}).get("service")},
        }

    service: dict | None = None

    if dig_path is None:
        errors.append("dig not found — required for this script (doctor.sh lists dig as "
                      "required; install bind9-dns-utils / bind-utils)")
        ev("dns: skipped — dig unavailable")
        return fail("INCONCLUSIVE", "no dig binary available, DNS pipeline not run")

    try:
        # ---- stage 1+2: DNS lookup / CNAME detection -----------------------
        chain = resolve_cname_chain(dig_path, domain, timeout)
        if len(chain) > 1:
            ev(f"dns: CNAME chain: {' -> '.join(chain)} ({len(chain) - 1} hop(s))")
        else:
            ev("dns: no CNAME record")

        wildcard, wc_detail = (False, "")
        if len(chain) > 1:
            wildcard, wc_detail = wildcard_parent_detected(dig_path, domain, timeout)
            ev("dns_state: parent-wildcard control — " + wc_detail)

        if len(chain) == 1:
            # short-circuit: no CNAME -> no dangling-CNAME vector. Try the NS variant + classify.
            input_status = dig_status(dig_path, domain, timeout)
            if input_status == "NXDOMAIN":
                ev("dns: input domain itself is NXDOMAIN — no records exist to hijack")
            ns = dig_short(dig_path, domain, "NS", timeout)
            if ns:
                ev("dns: NS delegation found: " + ", ".join(ns[:6]) +
                   (" ..." if len(ns) > 6 else ""))
                answering = 0
                for ns_host in ns[:MAX_NS_PROBES]:
                    out = dig_stdout(dig_path, ["@" + ns_host, "+time=" + str(int(max(1, timeout))),
                                                "+tries=1", "+short", domain, "SOA"],
                                     timeout, tolerate=True)
                    if out.strip():
                        answering += 1
                if answering:
                    ev(f"dns_state: {answering}/{len(ns[:MAX_NS_PROBES])} nameserver(s) "
                       f"answer SOA — delegation appears live/intentional")
                    return fail("NOT_VULNERABLE",
                                "NS delegation present and answering — no CNAME, delegation healthy",
                                NEXT_ACTION_BY_VERDICT["NOT_VULNERABLE"])
                ev("dns_state: NO listed nameserver answered SOA — delegation may point at a "
                   "deleted provider zone (NS-takeover primitive, subdomain-takeover.md §4)")
                return fail("POTENTIAL",
                            "NS-delegated subdomain with zero answering nameservers — possible "
                            "unclaimed provider zone",
                            "manual NS-takeover check: query each NS for SOA from a provider that "
                            "allows arbitrary zone creation (subdomain-takeover.md §4)")
            return fail("NOT_VULNERABLE",
                        "no CNAME present, no dangling-CNAME vector"
                        + (" (input is NXDOMAIN)" if input_status == "NXDOMAIN" else ""))

        # ---- stage 3+4: service identification / fingerprint match ---------
        target = chain[-1]
        service = match_service(target, fingerprints)
        if service is None:
            ev(f"service: CNAME target '{target}' does not match any known takeover-vulnerable "
               f"service — this is INCONCLUSIVE, not safe (fingerprint coverage is finite)")
            return fail("INCONCLUSIVE",
                        f"CNAME target '{target}' does not match any known takeover-vulnerable "
                        f"service")
        basis = service.get("confidence_basis", "unknown")
        ev(f"service: matched '{service['service']}' via pattern "
           f"({basis}) — {service.get('documentation', '')[:120]}")
        if basis != "well-documented":
            ev("service: confidence basis is community-report — verify manually before reporting")

        # ---- stage 5: DNS state analysis ------------------------------------
        nxd_expected = bool(service.get("nxdomain_expected"))
        resolves = check_target_resolves(dig_path, target, timeout)
        if resolves is True:
            ev(f"dns_state: CNAME target '{target}' resolves")
        elif resolves is False:
            ev(f"dns_state: CNAME target '{target}' is NXDOMAIN")
        else:
            ev(f"dns_state: CNAME target '{target}' resolution unknown (dig error/timeout)")

        dangling_nxdomain = resolves is False
        if nxd_expected and resolves is True:
            ev("dns_state: this service is NXDOMAIN-style when unclaimed, but the target "
               "resolves — service likely still claimed")
            verdict = "NOT_VULNERABLE"
            reason = "service's CNAME target still resolves — likely actively claimed"
            if wildcard:
                verdict, reason = "INCONCLUSIVE", "parent wildcard — the resolving target may be synthesized"
                return fail(verdict, reason)
            return fail(verdict, reason, conf=0.80)

        # ---- stage 6: service response analysis -----------------------------
        http_matched_fp: str | None = None
        http_got_response = False
        http_error: str | None = None
        fingerprints_body = [f.lower() for f in service.get("http_fingerprint", [])]

        if dangling_nxdomain and resolves is False:
            # The domain itself usually won't resolve in this state — probe anyway (cheap).
            ev("http: target NXDOMAIN — domain likely unreachable, probing anyway for completeness")
        for scheme in ("https", "http"):
            r = probe_http(f"{scheme}://{domain}/", timeout)
            if r["error"] is None:
                http_got_response = True
                ev(f"http: {scheme}://{domain}/ -> HTTP {r['status']} ({len(r['body'])}B body)")
                hit = next((fp for fp in fingerprints_body if fp in r["body"].lower()), None)
                if hit:
                    http_matched_fp = hit
                    ev(f"http: body fingerprint MATCHED: \"{hit}\"")
                elif fingerprints_body:
                    ev("http: no unclaimed-fingerprint string in body")
                else:
                    ev("http: no body fingerprint on record for this service — manual check "
                       "required")
                break
            http_error = r["error"]
        if not http_got_response:
            ev(f"http: probe failed ({http_error}) — treated as evidence, not a signal")

        # ---- stage 7: confidence / verdict ----------------------------------
        conf_override: float | None = None
        if http_matched_fp:
            verdict = "CONFIRMED"
            reason = f"CNAME pattern + provider's unclaimed body fingerprint both agree (\"{http_matched_fp}\")"
        elif dangling_nxdomain:
            verdict = "LIKELY"
            reason = "CNAME matches takeover-prone service AND target is NXDOMAIN (dangling)"
        elif http_got_response and not http_matched_fp and fingerprints_body:
            verdict = "NOT_VULNERABLE"
            conf_override = 0.70  # claimed-verdict: softer negative than the no-CNAME 0.95
            reason = "service serves content without its unclaimed signature — likely claimed"
        elif http_got_response:  # response but no fingerprint on record to test
            verdict = "POTENTIAL"
            reason = "CNAME matches takeover-prone service; no body fingerprint on record to confirm"
        else:
            verdict = "INCONCLUSIVE"
            reason = "CNAME matches a takeover-prone service but neither DNS state nor HTTP could be confirmed"

        if wildcard and verdict == "LIKELY":
            verdict, reason = "POTENTIAL", "downgraded: parent wildcard may synthesize the CNAME (" + wc_detail + ")"
        elif wildcard and verdict == "NOT_VULNERABLE" and reason.startswith("service serves content"):
            verdict, reason = "INCONCLUSIVE", "downgraded: parent wildcard — 'claimed' evidence unreliable"

        return fail(verdict, reason, conf=conf_override)

    except DigError as e:
        errors.append(str(e))
        ev(f"dns: dig failure — {e}")
        return fail("INCONCLUSIVE", "dig failed — DNS pipeline could not run")
    except Exception as e:  # never let one domain kill the run
        errors.append(f"unexpected error: {type(e).__name__}: {e}")
        return fail("INCONCLUSIVE", f"unexpected error during scan: {e}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def load_domain_list(path: str) -> list[str]:
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
    actionable = []
    for r in results:
        if r["findings"]:
            f = r["findings"][0]
            line = r["evidence"][-1] if r["evidence"] else "no evidence"
            eprint(f"[{r['target']}] {line}")
            if f["severity"] != "info":
                actionable.append(f)
        for err in r["errors"]:
            eprint(f"[{r['target']}] ERROR: {err}")
    if actionable:
        eprint("")
        for f in actionable:
            eprint(f"  -> [{f['target']}] {f['verdict']}: {f['next_action']}")
    eprint("")
    eprint("Next: re-run interesting targets with --verbose for the stage-by-stage evidence, "
           "then confirm by claiming the resource (subdomain-takeover.md §3) before reporting")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=SOURCE,
        description="Dangling-DNS / subdomain-takeover candidate detector "
                    "(CNAME + NS best-effort; fingerprint + DNS-state + HTTP evidence required).",
        epilog="examples:\n"
               "  %(prog)s sub.target.com\n"
               "  %(prog)s -l recon/subs.txt --json --output takeovers.json --threads 20\n"
               "  %(prog)s sub.target.com --verbose   # stage-by-stage evidence to stderr\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains", nargs="*", metavar="domain",
                    help="domain(s) to check")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file of domains, one per line (# comments allowed)")
    ap.add_argument("--json", action="store_true",
                    help="machine output on stdout (normalized JSON; array when >1 domain)")
    ap.add_argument("--timeout", type=float, default=5.0, metavar="SEC",
                    help="per-DNS/HTTP-operation timeout in seconds (default: 5)")
    ap.add_argument("--threads", type=int, default=10, metavar="N",
                    help="concurrent workers for multiple domains (default: 10)")
    ap.add_argument("--output", metavar="FILE",
                    help="also write the JSON result(s) to this file")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress the human-readable summary (no effect with --json)")
    ap.add_argument("--verbose", action="store_true",
                    help="print each pipeline stage's evidence to stderr as it runs")
    args = ap.parse_args(argv)

    domains: list[str] = list(args.domains)
    if args.list:
        try:
            domains.extend(load_domain_list(args.list))
        except (OSError, FileNotFoundError) as e:
            eprint(f"[!] {e}")
            return 2
    if not domains:
        ap.error("no domains given (positional args or -l/--list FILE)")
    if args.timeout <= 0:
        ap.error("--timeout must be > 0")
    if args.threads < 1:
        ap.error("--threads must be >= 1")

    # dedupe, preserve order
    seen: set[str] = set()
    domains = [d for d in domains if not (d.lower() in seen or seen.add(d.lower()))]

    try:
        fingerprints = load_fingerprints()
    except (OSError, ValueError) as e:
        eprint(f"[!] cannot load fingerprint DB {FINGERPRINTS_FILE}: {e}")
        return 2

    dig_path = find_tool("dig")
    if dig_path is None and not args.quiet:
        eprint("[!] dig not found on PATH or common install dirs — every domain will be "
               "INCONCLUSIVE (see scripts/doctor.sh)")

    if not args.quiet and not args.json:
        eprint(f"[*] {TOOL}: {len(domains)} domain(s) | fingerprints: {len(fingerprints)} | "
               f"dig: {dig_path or 'MISSING'} | timeout: {args.timeout}s")

    def run_one(d: str) -> dict:
        return scan_domain(d, fingerprints, timeout=args.timeout,
                           dig_path=dig_path, verbose=args.verbose)

    if len(domains) == 1:
        results = [run_one(domains[0])]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, len(domains))) as ex:
            futures = {ex.submit(run_one, d): d for d in domains}
            by_domain: dict[str, dict] = {}
            for fut in concurrent.futures.as_completed(futures):
                by_domain[futures[fut]] = fut.result()
            results = [by_domain[d] for d in domains]  # preserve input order

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
