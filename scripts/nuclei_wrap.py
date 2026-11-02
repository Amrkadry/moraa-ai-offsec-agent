#!/usr/bin/env python3
"""nuclei_wrap.py — THIN wrapper around ProjectDiscovery's nuclei (recon.md §7), NOT a
template engine.

WHY: nuclei already ships ~10k curated community templates with its own matching and
severity classification. Reimplementing any of that would be worse at it and would
drift — the exact reasoning that makes github_recon.py a wrapper and not a secret
scanner. This script's whole job:

    TARGETS -> find_tool("nuclei") -> BUILD FLAG SET -> subprocess (argument LIST, never
    shell=True) -> -jsonl on stdout -> one finding per line -> repo JSON contract

  1. TOOL DISCOVERY  find_tool() — python mirror of lib/tools.sh, same pattern as
                     subdomain_takeover.py / github_recon.py. nuclei NOT installed ->
                     CLEAN SKIP: success-status result, empty findings, one clear
                     evidence/error line with the install command, exit 0. Non-zero exit
                     is reserved for bad arguments only.
  2. FLAG SET        Default = recon.md §7's quick-wins sweep, verbatim:
                       -tags exposure,config,git,backup,takeover -severity critical,high,medium
                     ADAPTIVE: --from-cms-detect <cms_detect.py --json output> (single
                     result object OR the array-of-results form) adds the identified
                     CMS's own nuclei tag (nuclei's tag convention is the lowercased CMS
                     name: wordpress/joomla/drupal/moodle) for THAT target only, on top
                     of the default set. Targets are grouped by effective tag set and
                     nuclei runs ONCE PER GROUP — a WordPress host gets
                     ...takeover,wordpress while an unidentified host gets the plain
                     defaults — never one giant unioned tag list across mismatched hosts
                     (the repo's adaptive / no-blind-sweep discipline).
  3. EXECUTION       -u <target> for a single-target group, -l <tempfile> for a group of
                     several; always -jsonl -silent -no-color so stdout is pure JSONL
                     (banner/progress stay on stderr); -timeout <SEC> is nuclei's own
                     per-request timeout; -rl is passed through ONLY when --rate-limit
                     is given — omit the flag and nuclei's own default (150 rps) applies
                     (nuclei's rate limiting is trusted; this wrapper does not need to
                     be more conservative than the tool it wraps).
  4. MAPPING         nuclei's own JSONL fields map 1:1 into the contract — template-id,
                     info.name, info.severity (PASSED THROUGH UNCHANGED: info/low/
                     medium/high/critical/unknown), matched-at, extracted-results.
                     Nothing re-derived, nothing second-guessed. This is the ONE place
                     in this repo where an upstream "critical" passes through as-is,
                     because nuclei templates are community-curated and its severity
                     field is the actual signal, not a guess this script makes.
                     Confidence is a FIXED 0.85 — curated templates, not a regex guess,
                     but NEVER 1.0 (templates do false-positive).
  5. DEGRADATION     unparseable JSONL lines are skipped and counted, never fatal; a
                     nonzero nuclei exit (template compile error, etc.) is recorded as
                     an error while any findings that streamed before the failure are
                     still parsed — nuclei emits results progressively (same reasoning
                     as github_recon.py's trufflehog handling). matcher-status=false
                     lines (template ran, did not match) are not findings.

Evidence discipline: nuclei's JSONL also carries raw request/response/curl-command
blobs — potentially large and potentially payload/credential material. They are
deliberately NOT copied into evidence. Evidence carries template-id / name /
matched-at / extracted-results only; re-running the template manually
(nuclei -id <template-id> -u <target>) is the confirmation step.

Timeouts: --timeout (default 10) is nuclei's PER-REQUEST timeout (-timeout). The
wrapper's own wall clock per nuclei invocation is TOOL_TIMEOUT_S (900s) — a tag-scoped
sweep over a target list is legitimately minutes; a short wall clock would guarantee
false "tool failed" results (same reasoning as github_recon.py's wrapped tools).

Exit code: 0 for a completed run — including "nuclei not installed" (a clean skip is a
valid, reportable outcome) and including a nuclei nonzero exit (recorded in errors).
Non-zero (2) only for hard argument errors: no targets, missing/unreadable -l file,
missing/unparseable --from-cms-detect file, --timeout <= 0, --rate-limit < 1.

Zero third-party pip packages — subprocess to nuclei is the whole point (house rule).
Python 3 stdlib only.

Usage:
    python3 nuclei_wrap.py https://target.example
    python3 nuclei_wrap.py -l recon/live.txt --json --output nuclei.json
    python3 nuclei_wrap.py -l recon/live.txt --from-cms-detect recon/cms.json --json
    python3 nuclei_wrap.py -u https://target.example --tags exposure,config --severity high,critical
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

TOOL = "nuclei_wrap"
SOURCE = "nuclei_wrap.py"

# recon.md §7 quick-wins sweep, verbatim (the doc's exact flag values).
DEFAULT_TAGS = "exposure,config,git,backup,takeover"
DEFAULT_SEVERITY = "critical,high,medium"

# nuclei-templates.md / templates/: every template in the repo's local set carries this tag,
# so when --local-templates is on the tag gets appended to the effective -tags filter and
# nuclei still LOADS them (nuclei applies -tags as a filter over -t directories too — a
# template whose tags miss the filter is silently skipped). Custom templates additionally
# carry a default-sweep tag (exposure/...) so they ride along without the flag as well.
LOCAL_TEMPLATE_TAG = "moraa"


def default_local_templates_dir() -> str | None:
    """The repo's own templates/ dir (../templates relative to this script) — the --local-templates
    default. None when the dir doesn't exist (flag then behaves like an explicit bad path)."""
    d = Path(__file__).resolve().parent.parent / "templates"
    return str(d) if d.is_dir() else None

NUCLEI_INSTALL_CMD = "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

DEFAULT_TIMEOUT = 10         # nuclei's own per-request default (-timeout)
TOOL_TIMEOUT_S = 900.0       # wall clock per nuclei invocation (target lists take minutes)
VERSION_TIMEOUT_S = 60.0     # `nuclei -version` is cosmetic metadata, not a scan
FINDING_CONFIDENCE = 0.85    # curated templates, not a regex guess — but never 1.0

# Mirrors scripts/lib/tools.sh's extra search dirs so bash and python tooling find the
# same binaries (a non-login shell often lacks ~/go/bin on PATH).
EXTRA_TOOL_DIRS = (
    "~/go/bin",
    "~/.local/go/bin",
    "~/.local/bin",
    "/usr/local/bin",
    "/usr/local/sbin",
)


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


def get_nuclei_version(nuclei_path: str) -> str | None:
    """`nuclei -version` for metadata.nuclei_version — purely cosmetic. A failure here
    does NOT make nuclei 'missing' (find_tool already found the binary)."""
    rc, out, err = run_tool([nuclei_path, "-version"], VERSION_TIMEOUT_S)
    m = re.search(r"Version:\s*(v?[0-9][\w.\-]*)", (out or "") + "\n" + (err or ""))
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# target / tag-set handling (the ADAPTIVE part — grouping, not template logic)
# --------------------------------------------------------------------------

def _norm_target(t: str) -> str:
    """Normalization for MATCHING scan targets against cms_detect targets only —
    whatever the user passed is still what gets fed to nuclei verbatim."""
    s = t.strip().lower()
    for scheme in ("https://", "http://"):
        if s.startswith(scheme):
            s = s[len(scheme):]
    return s.rstrip("/")


def _effective_tags(base_tags: str, cms: str | None, local_templates: bool = False) -> str:
    """Default (or --tags) set + the CMS's own nuclei tag (lowercased CMS name —
    nuclei's tag convention) + the LOCAL_TEMPLATE_TAG when the local templates dir is in
    play, deduped, order preserved."""
    parts = [p.strip() for p in base_tags.split(",") if p.strip()]
    if cms:
        tag = cms.strip().lower()
        if tag and tag not in parts:
            parts.append(tag)
    if local_templates and LOCAL_TEMPLATE_TAG not in parts:
        parts.append(LOCAL_TEMPLATE_TAG)
    return ",".join(parts)


def load_cms_map(path: str) -> dict[str, str]:
    """Parse cms_detect.py --json output (SINGLE result object OR the array-of-results
    form) into {normalized-target: cms} for every target where a CMS was identified
    (cms_detect puts the CMS name on its cms_detection finding's "cms" key; hosts with
    no identification have cms=null and are simply absent from the map -> default tags).
    Raises ValueError for a missing/unparseable file — the caller turns that into a
    hard argument error (the user explicitly asked for adaptive mode)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise ValueError("cannot read --from-cms-detect file %s: %s" % (path, e))
    results = data if isinstance(data, list) else [data]
    cms_map: dict[str, str] = {}
    for entry in results:
        if not isinstance(entry, dict):
            continue
        target = entry.get("target")
        if not isinstance(target, str) or not target:
            continue
        findings = entry.get("findings")
        for f in findings if isinstance(findings, list) else []:
            if isinstance(f, dict) and f.get("cms"):
                cms_map[_norm_target(target)] = str(f["cms"]).strip()
                break
    return cms_map


def build_run_groups(targets: list[str], cms_map: dict[str, str] | None,
                     base_tags: str, local_templates: bool = False) -> list[dict]:
    """Group targets by EFFECTIVE tag set, preserving first-appearance order. Each group
    gets its own nuclei invocation — targeted per tag set, never a unioned sweep."""
    groups: list[dict] = []
    by_tags: dict[str, dict] = {}
    cms_map = cms_map or {}
    for t in targets:
        cms = cms_map.get(_norm_target(t))
        tags = _effective_tags(base_tags, cms, local_templates)
        g = by_tags.get(tags)
        if g is None:
            g = {"tags": tags, "targets": []}
            by_tags[tags] = g
            groups.append(g)
        g["targets"].append(t)
    return groups


# --------------------------------------------------------------------------
# nuclei JSONL -> repo contract (MAP nuclei's own fields; never re-derive)
# --------------------------------------------------------------------------

def parse_nuclei_jsonl(text: str) -> tuple[list[dict], int]:
    """One JSON object per line; unparseable lines (banners, partial writes) are
    counted, never fatal."""
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
        else:
            bad += 1
    return out, bad


def map_finding(obj: dict) -> dict:
    """ONE nuclei JSONL result -> ONE contract finding. nuclei's severity string passes
    through UNCHANGED (info/low/medium/high/critical/unknown) — mapped, never
    re-classified. Confidence is the fixed FINDING_CONFIDENCE (curated templates, never
    1.0). request/response/curl-command blobs are deliberately NOT copied (docstring,
    evidence discipline)."""
    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    template_id = str(obj.get("template-id") or obj.get("templateID")
                      or "(unknown-template)")
    name = str(info.get("name") or "(unnamed template)")
    severity = str(info.get("severity") or "unknown")     # PASSTHROUGH — the actual signal
    matched_at = str(obj.get("matched-at") or obj.get("matched")
                     or obj.get("host") or "(unknown)")
    extracted = obj.get("extracted-results")
    extracted = [str(e) for e in extracted] if isinstance(extracted, list) else []

    evidence = [
        "template-id: %s" % template_id,
        "name: %s" % name,
        "matched-at: %s" % matched_at,
    ]
    if extracted:
        evidence.append("extracted-results: %s" % "; ".join(extracted))

    reference = info.get("reference")
    if isinstance(reference, list):
        reference = reference[0] if reference else None
    if reference:
        next_action = ("confirm manually -- nuclei template %s: %s, see %s"
                       % (template_id, name, reference))
    else:
        next_action = "confirm manually -- nuclei template %s: %s" % (template_id, name)

    return {
        "type": "nuclei_finding",
        "severity": severity,
        "confidence": FINDING_CONFIDENCE,
        "target": matched_at,
        "evidence": evidence,
        "source": SOURCE,
        "template_id": template_id,
        "template_name": name,
        "host": obj.get("host"),
        "next_action": next_action,
    }


def run_nuclei_group(nuclei_path: str, tags: str, severity: str, timeout: int,
                     rate_limit: int | None, targets: list[str],
                     local_templates_dir: str | None = None,
                     verbose: bool = False) -> dict:
    """ONE nuclei invocation for ONE tag-set group: -u for a single target, -l for a
    group list (temp target file, cleaned up). A nonzero rc is an error, not a crash —
    results streamed before the failure are still parsed (nuclei emits progressively)."""
    findings: list[dict] = []
    evidence: list[str] = []
    errors: list[str] = []
    fd, listfile = tempfile.mkstemp(prefix="nuclei_wrap_targets_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tf:
            if len(targets) > 1:
                tf.write("\n".join(targets) + "\n")
        argv = [nuclei_path, "-tags", tags, "-severity", severity,
                "-jsonl", "-silent", "-no-color",
                "-timeout", str(timeout)]
        if local_templates_dir:
            argv += ["-t", local_templates_dir]
        if rate_limit is not None:
            argv += ["-rl", str(rate_limit)]
        if len(targets) == 1:
            argv += ["-u", targets[0]]
        else:
            argv += ["-l", listfile]
        if verbose:
            eprint("  [nuclei] %s" % " ".join(argv))
        rc, out, err = run_tool(argv, TOOL_TIMEOUT_S)
    finally:
        try:
            os.unlink(listfile)
        except OSError:
            pass

    evidence.append("nuclei run: tags=%s severity=%s targets=%d (%s%s)"
                    % (tags, severity, len(targets),
                       "-u" if len(targets) == 1 else "-l",
                       " +local-templates:%s" % local_templates_dir
                       if local_templates_dir else ""))

    objs, bad = parse_nuclei_jsonl(out)
    nonmatch = 0
    for obj in objs:
        if obj.get("matcher-status") is False:
            nonmatch += 1       # template ran, did not match: not a finding
            continue
        findings.append(map_finding(obj))

    if rc == 0:
        evidence.append("nuclei: completed (rc=0), %d result line(s), %d unparseable"
                        % (len(objs), bad))
    elif rc is None:
        errors.append("nuclei: %s" % (err.strip() or "unknown failure"))
    else:
        errors.append("nuclei: rc=%s %s" % (rc, err.strip()[:300]))
        evidence.append("nuclei: exited rc=%s — result lines streamed before the failure "
                        "were still parsed" % rc)
    if bad:
        evidence.append("nuclei: %d unparseable stdout line(s) skipped" % bad)

    return {"findings": findings, "evidence": evidence, "errors": errors,
            "rc": rc, "result_lines": len(objs), "bad_lines": bad,
            "non_matching": nonmatch}


# --------------------------------------------------------------------------
# the wrapper
# --------------------------------------------------------------------------

def scan_nuclei(targets: list[str], cms_map: dict[str, str] | None = None,
                base_tags: str = DEFAULT_TAGS, severity: str = DEFAULT_SEVERITY,
                timeout: int = DEFAULT_TIMEOUT, rate_limit: int | None = None,
                local_templates: str | None = None,
                verbose: bool = False) -> dict:
    """Run nuclei once per tag-set group over the given targets; normalize whatever
    actually ran into ONE aggregate result object. With local_templates set, the repo's
    templates/ dir is added via -t on every run and LOCAL_TEMPLATE_TAG is appended to each
    group's effective tag set so nuclei still loads them under the -tags filter."""
    target_desc = targets[0] if len(targets) == 1 else "%d targets" % len(targets)
    adaptive = bool(cms_map)
    nuclei_path = find_tool("nuclei")

    findings: list[dict] = []
    evidence: list[str] = ["scope: %s" % target_desc,
                           "severity filter: %s" % severity]
    errors: list[str] = []
    tags_used: list[dict] = []
    runs: list[dict] = []
    raw_count = bad_total = nonmatch_total = 0
    version: str | None = None

    if local_templates:
        n_yaml = len(list(Path(local_templates).glob("*.yaml")))
        evidence.append("local templates: %s (%d .yaml file(s), +%s tag) — see "
                        "nuclei-templates.md for the vulnerable/clean-control workflow"
                        % (local_templates, n_yaml, LOCAL_TEMPLATE_TAG))

    if adaptive:
        for t in targets:
            cms = (cms_map or {}).get(_norm_target(t))
            evidence.append("adaptive: %s -> %s" % (
                t, "cms_detect identified %s (+%s tag)" % (cms, cms.strip().lower())
                if cms else "no CMS identified (default tags)"))

    if nuclei_path is None:
        skip = ("nuclei is not installed (find_tool checked PATH + %s) — clean SKIP, "
                "nothing scanned; install with: %s"
                % (", ".join(EXTRA_TOOL_DIRS), NUCLEI_INSTALL_CMD))
        errors.append(skip)
        evidence.append(skip)
    else:
        version = get_nuclei_version(nuclei_path)
        groups = build_run_groups(targets, cms_map, base_tags,
                                  local_templates=bool(local_templates))
        for i, g in enumerate(groups, 1):
            if verbose:
                eprint("[*] nuclei run %d/%d: tags=%s targets=%d"
                       % (i, len(groups), g["tags"], len(g["targets"])))
            r = run_nuclei_group(nuclei_path, g["tags"], severity, timeout,
                                 rate_limit, g["targets"], local_templates,
                                 verbose)
            findings.extend(r["findings"])
            evidence.extend(r["evidence"])
            errors.extend(r["errors"])
            raw_count += len(r["findings"])
            bad_total += r["bad_lines"]
            nonmatch_total += r["non_matching"]
            tags_used.append({"tags": g["tags"], "targets": list(g["targets"])})
            runs.append({"tags": g["tags"], "target_count": len(g["targets"]),
                         "rc": r["rc"], "findings": len(r["findings"]),
                         "unparseable_lines": r["bad_lines"]})

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    if not tags_used:
        tags_used = [{"tags": _effective_tags(base_tags, None, bool(local_templates)),
                      "targets": list(targets)}]  # the set that WOULD have run

    return {
        "tool": TOOL,
        "target": target_desc,
        "timestamp": now_iso(),
        "status": "success",
        "findings": findings,
        "evidence": evidence,
        "errors": errors,
        "metadata": {
            "nuclei_path": nuclei_path,
            "nuclei_version": version,
            "tags_used": tags_used,
            "severity_filter": severity,
            "targets_scanned": len(targets) if nuclei_path else 0,
            "raw_finding_count": raw_count,
            "unparseable_lines": bad_total,
            "non_matching_results": nonmatch_total,
            "per_request_timeout_s": timeout,
            "rate_limit": rate_limit,   # None = -rl omitted -> nuclei's own default (150)
            "adaptive_cms_tags": adaptive,
            "from_cms_detect": bool(cms_map),
            "local_templates": local_templates,
            "tool_timeout_s": TOOL_TIMEOUT_S,
            "runs": runs,
            "totals": {"findings_by_severity": by_sev},
        },
    }


# --------------------------------------------------------------------------
# CLI (conventions shared with cms_detect.py / js_recon.py / github_recon.py)
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
    md = result["metadata"]
    if md["nuclei_path"] is None:
        eprint("[skip] nuclei — %s" % (result["errors"][0] if result["errors"]
                                       else "not installed"))
    else:
        eprint("[*] nuclei %s at %s | rate-limit: %s"
               % (md["nuclei_version"] or "unknown", md["nuclei_path"],
                  ("nuclei default (150 rps)" if md["rate_limit"] is None
                   else md["rate_limit"])))
        for run in md["runs"]:
            eprint("[*] run: tags=%s targets=%d -> %d finding(s) (rc=%s)"
                   % (run["tags"], run["target_count"], run["findings"], run["rc"]))
        if md.get("local_templates"):
            eprint("[*] local templates: %s (+%s tag)"
                   % (md["local_templates"], LOCAL_TEMPLATE_TAG))
    for f in result["findings"]:
        eprint("[%s] %s (confidence %.2f) — %s" % (
            f["severity"].upper(), f["target"], f["confidence"],
            f["next_action"]))
    for err in result["errors"]:
        if result["findings"] or md["nuclei_path"] is not None:
            eprint("ERROR: %s" % err)
    eprint("")
    eprint("totals: %d nuclei finding(s) %s | %d target(s) | %d run(s)%s"
           % (len(result["findings"]),
              md["totals"]["findings_by_severity"] or "(all clean)",
              md["targets_scanned"], len(md["runs"]),
              ", %d unparseable line(s) skipped" % md["unparseable_lines"]
              if md["unparseable_lines"] else ""))
    eprint("")
    eprint("Next: confirm every nuclei_finding MANUALLY before reporting — curated "
           "templates still false-positive (confidence 0.85, never proof); re-run the "
           "template by id for the evidence chain (nuclei -id <template-id> -u "
           "<target>), validate per validate.md, and record the sweep in coverage.md")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=SOURCE,
        description="THIN wrapper around ProjectDiscovery's nuclei (recon.md §7 "
                    "quick-wins), NOT a template engine: builds the default "
                    "(-tags exposure,config,git,backup,takeover -severity "
                    "critical,high,medium) or an ADAPTIVE tag set from a cms_detect.py "
                    "--json file (--from-cms-detect: identified CMS -> +<cms> tag for "
                    "that target, one nuclei run per tag-set group), runs nuclei with "
                    "-jsonl, and maps its OWN template-id/severity/matched-at fields "
                    "into the repo finding contract — severities pass through unchanged, "
                    "nothing re-derived. nuclei missing -> clean skip (exit 0).",
        epilog="examples:\n"
               "  %(prog)s https://target.example\n"
               "  %(prog)s -l recon/live.txt --json --output nuclei.json\n"
               "  %(prog)s -l recon/live.txt --from-cms-detect recon/cms.json --json\n"
               "  %(prog)s -u https://target.example --tags exposure,config "
               "--severity high,critical --rate-limit 75\n"
               "  %(prog)s -u https://target.example --local-templates --verbose\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", metavar="target",
                    help="target URL(s) or bare host(s), as for nuclei -u")
    ap.add_argument("-u", "--target", dest="u_targets", action="append", metavar="TARGET",
                    help="target URL/host (nuclei's own -u letter; repeatable, same pool "
                         "as positional targets)")
    ap.add_argument("-l", "--list", metavar="FILE",
                    help="file of targets, one per line (# comments allowed) — nuclei's "
                         "own -l convention")
    ap.add_argument("--from-cms-detect", dest="from_cms_detect", metavar="FILE",
                    help="cms_detect.py --json output (single object or array); for "
                         "every target where a CMS was identified, add its nuclei tag "
                         "(lowercased CMS name) on top of the default tags, grouped per "
                         "target so each tag-set gets its own nuclei run")
    ap.add_argument("--local-templates", dest="local_templates", nargs="?",
                    const=default_local_templates_dir(), default=None, metavar="DIR",
                    help="also load the repo's own high-signal template dir (default: "
                         "<repo>/templates — %s) via -t, tagging each run +%s so the "
                         "-tags filter still loads them; validate first per "
                         "nuclei-templates.md (nuclei -validate -t templates/)"
                         % (default_local_templates_dir() or "<repo>/templates missing",
                            LOCAL_TEMPLATE_TAG))
    ap.add_argument("--tags", default=DEFAULT_TAGS, metavar="CSV",
                    help="nuclei -tags (default: %(default)s — recon.md §7 quick-wins; "
                         "overrides the default set entirely; --from-cms-detect tags "
                         "are still added on top of YOUR set)")
    ap.add_argument("--severity", default=DEFAULT_SEVERITY, metavar="CSV",
                    help="nuclei -severity (default: %(default)s; passed through to "
                         "nuclei's own filter)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SEC",
                    help="nuclei -timeout: per-REQUEST timeout in seconds "
                         "(default: %(default)s, nuclei's own default)")
    ap.add_argument("--rate-limit", dest="rate_limit", type=int, default=None,
                    metavar="RPS",
                    help="nuclei -rl: requests/second cap. Optional — when omitted the "
                         "-rl flag is omitted entirely and nuclei's own default (150 "
                         "rps) applies")
    ap.add_argument("--json", action="store_true",
                    help="machine output on stdout (normalized JSON; ONE object per run)")
    ap.add_argument("--output", metavar="FILE",
                    help="also write the JSON result to this file")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress the human-readable summary (no effect with --json)")
    ap.add_argument("--verbose", action="store_true",
                    help="print each nuclei run's progress to stderr as it happens")
    args = ap.parse_args(argv)

    targets: list[str] = list(args.targets)
    if args.u_targets:
        targets.extend(args.u_targets)
    if args.list:
        try:
            targets.extend(load_target_list(args.list))
        except (OSError, FileNotFoundError) as e:
            eprint(f"[!] {e}")
            return 2
    if not targets:
        ap.error("no targets given (positional args, -u/--target, or -l/--list FILE)")
    if args.timeout <= 0:
        ap.error("--timeout must be > 0")
    if args.rate_limit is not None and args.rate_limit < 1:
        ap.error("--rate-limit must be >= 1 (omit the flag to use nuclei's own default)")
    if args.local_templates is not None and not Path(args.local_templates).is_dir():
        eprint(f"[!] --local-templates dir not found: {args.local_templates}")
        return 2

    # dedupe, preserve order
    seen: set = set()
    targets = [t for t in targets if not (t.strip() in seen or seen.add(t.strip()))]

    cms_map: dict[str, str] | None = None
    if args.from_cms_detect:
        try:
            cms_map = load_cms_map(args.from_cms_detect)
        except ValueError as e:
            eprint(f"[!] {e}")
            return 2
        if not args.quiet and not args.json:
            identified = ", ".join(sorted(set(cms_map.values()))) or "no CMS identified"
            eprint("[*] adaptive tags from %s: %s" % (args.from_cms_detect, identified))

    if not args.quiet and not args.json:
        eprint("[*] %s: %d target(s) | tags: %s | severity: %s | per-request timeout: "
               "%ss | rate-limit: %s%s" % (
                   TOOL, len(targets), args.tags, args.severity, args.timeout,
                   "nuclei default (150)" if args.rate_limit is None
                   else args.rate_limit,
                   " | local-templates: %s" % args.local_templates
                   if args.local_templates else ""))
        if not find_tool("nuclei"):
            eprint("[*] nuclei not found — will report a clean skip (install: %s)"
                   % NUCLEI_INSTALL_CMD)

    result = scan_nuclei(targets=targets, cms_map=cms_map, base_tags=args.tags,
                         severity=args.severity, timeout=args.timeout,
                         rate_limit=args.rate_limit,
                         local_templates=args.local_templates, verbose=args.verbose)

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

    return 0  # completed run — a clean nuclei-missing skip is a valid outcome, not an error


if __name__ == "__main__":
    sys.exit(main())
