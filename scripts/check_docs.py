#!/usr/bin/env python3
"""
check_docs.py — make the skill library self-checking (structural lint over the .md corpus).

WHY: a doc gave WRONG advice for months (recon.md told you to DNS-resolve a CT name to verify
it — which "confirms" invented hosts on any wildcard domain) and nothing caught it. Prose rots
quietly: technique docs lose their commands, code fences drift out of balance, wiki-links point
at files renamed away, new docs get written but never wired into the router. This script turns
each of those recurring failure modes into a deterministic check so `python3 scripts/check_docs.py`
can gate a session or a commit the way a test suite gates code.

Checks (exit non-zero if ANY fails):
  1. zero-fence docs     — root technique docs with no runnable commands (commands-first
                           violation); agent role files under agents/ are exempt from THIS check
                           (their commands live in the class docs they route to) but still get
                           the wiki-link and fence-balance checks
  2. unbalanced fences   — odd number of ``` markers in a file (truncated edit / broken block)
  3. [[wiki-links]]      — every [[name]] must resolve to a real file in this repo
  4. ROUTER integrity    — every .md referenced by SKILL.md's ROUTER table must exist; every
                           root-level .md must be referenced by it (orphans reported), minus
                           the MANUAL-ONLY docs (deliberately unrouted) and meta allowlist
  5. web-hunt coverage   — every root doc the ROUTER wires in must also be referenced in
                           web-hunt.md: bughunter STEP 3 follows web-hunt's class table, so a
                           class wired into SKILL.md but absent there is invisible to the hunter
  6. MANUAL-ONLY invariant — captcha-bypass.md and web-cache.md appear ONLY inside SKILL.md's
                           MANUAL-ONLY section, and NOT AT ALL in web-hunt.md
  7. gate substance (INFO, never FAIL) — technique docs carrying NEITHER gate-substance phrasing
                           ("proves nothing", "= Low", "not a finding", "proof bar", "alone is")
                           NOR an impact-gate heading are listed as INFO. Deliberately not a
                           heading-presence lint: gate SUBSTANCE under other names counts, and
                           heading quotas would turn gating into a compliance checkbox.
  8. validate.md pointer — an agent file referencing validate.md must resolve to the ROOT doc;
                           any reference to the knowledge/bug-bounty copy is a FAIL (finder and
                           gatekeeper once graded against different rubrics — see AGENTS.md)
  9. agent mirror drift (WARN) — agents/*.md diffed against ~/.claude/agents/*.md; divergence
                           warns, never fails (the canonical copy is updated + re-mirrored by
                           the orchestrator). AGENTS.md records these mirrors silently losing
                           their Burp tool grants once; this mechanizes catching it.

Scope: repo root *.md, agents/*.md, payloads/*.md. knowledge/ is excluded on purpose — it is
vendored upstream corpus we do not maintain (see AGENTS.md). docs/ (engagement/process notes)
is excluded from the fence checks (prose by design) but counted as a link-target directory.
*.bak* files are excluded, and stale backups live in bak/ (moved out of the scanned corpus so
Grep/Glob over the skill folder never reads stale advice side-by-side with current advice).

Usage:
    python3 scripts/check_docs.py            # from the repo root
    python3 scripts/check_docs.py --quiet    # only output on failure

Pure python3 standard library. Run it after any doc change; exit 0 = structurally sound.
"""
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MANUAL_ONLY_DOCS = ("captcha-bypass.md", "web-cache.md")
# Root docs that are meta/orchestration, deliberately not wired into the ROUTER table:
#   SKILL.md is the router itself; README/AGENTS are repo meta; CUSTOM-WORKFLOW.md is the design
#   rationale (referenced from SKILL.md prose); CUSTOMIZATION.md and SECURITY.md are public-release
#   meta; AUDIT-*.md are dated audit logs.
ORPHAN_ALLOWLIST = {"SKILL.md", "README.md", "AGENTS.md", "CUSTOM-WORKFLOW.md",
                    "CUSTOMIZATION.md", "SECURITY.md"}
AUDIT_RE = re.compile(r"^AUDIT-\d{4}-\d{2}-\d{2}\.md$")

# Policy/meta docs that are prose by design: the commands-first rule applies to technique docs,
# not to a licence-adjacent security policy or a tier map.
NO_COMMAND_DOCS = {"SECURITY.md"}

# Root docs legitimately ABSENT from web-hunt.md even though the ROUTER wires them: the
# internal/AD track (bughunter STEP 3 is web-only), repo meta/routing docs, and niche classes
# with their own SKILL router rows and no place in the web class table. Anything NOT here and
# NOT in web-hunt.md is a FAIL — that is exactly the "wired into SKILL.md, invisible to the
# hunter" gap. Extend this list only with a stated reason.
WEBHUNT_ABSENT_OK = {
    # internal / AD / post-footmark track
    "active-directory.md", "pivoting.md", "dcsync.md", "privesc-windows.md",
    "privesc-linux.md", "lateral-movement.md", "credential-access.md",
    "file-transfer.md", "persistence.md", "cheatsheet.md",
    # meta / orchestration / tooling
    "web-hunt.md", "burp-mcp.md", "glm-delegation.md", "fleet-discipline.md",
    "engagement-ceiling.md", "cloud-offensive.md",
    # niche non-web classes with dedicated router rows
    "agentic-browser-hijack.md", "mcp-security.md", "web3-audit.md", "meme-coin-audit.md",
    # offline binary/firmware analysis: no live web surface, so no web class-table row
    "binary-diffing.md",
    # harness/verdict discipline: applies to every class, belongs beside validate.md not in the table
    "poc-discipline.md",
}

# Gate-substance markers: if a technique doc contains any of these (or an impact-gate heading),
# the proof bar exists in some form. Neither → INFO only (see check 7 in the docstring).
GATE_SUBSTANCE = ("proves nothing", "= low", "not a finding", "proof bar", "alone is")
GATE_HEADING_RE = re.compile(r"^#+ .*impact gate", re.I | re.M)

# The canonical agent definitions (see AGENTS.md: ~/.claude/agents/ is canonical, repo agents/
# are mirrors). Drift is a WARN, not a FAIL — canonical is re-mirrored by the orchestrator.
CANONICAL_AGENTS_DIR = os.path.expanduser(os.path.join("~", ".claude", "agents"))

FENCE = "```"


def scan_files():
    """Root + agents/ + payloads/ markdown; *.bak* and the bak/ backup dir never scanned."""
    files = []
    for sub in (".", "agents", "payloads"):
        if sub == "bak":  # defensive: stale backups stay out of the corpus
            continue
        d = os.path.join(REPO, sub)
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.endswith(".md") and ".bak" not in f:
                files.append(os.path.normpath(os.path.join(sub, f)))
    return files


def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def link_targets_exist(name, linking_file):
    """A [[name]] resolves if <name>.md exists at root, agents/, payloads/, docs/, the linking
    file's own directory, or via a path-qualified link relative to the linking file."""
    cand = name if name.endswith(".md") else name + ".md"
    bases = [
        REPO,
        os.path.join(REPO, "agents"),
        os.path.join(REPO, "payloads"),
        os.path.join(REPO, "docs"),
        os.path.dirname(os.path.join(REPO, linking_file)),
    ]
    for base in bases:
        p = os.path.normpath(os.path.join(base, cand))
        if os.path.isfile(p):
            return True
    return False


def manual_only_section(text):
    """Return (start, end) char offsets of SKILL.md's '## MANUAL-ONLY' section (up to the next
    top-level '## ' heading or EOF), or None."""
    m = re.search(r"^## MANUAL-ONLY\b.*$", text, re.M)
    if not m:
        return None
    start = m.start()
    nxt = re.search(r"^## (?!MANUAL-ONLY)", text[m.end():], re.M)
    end = len(text) if not nxt else m.end() + nxt.start()
    return (start, end)


def router_section(text):
    m = re.search(r"^## ROUTER\b.*$", text, re.M)
    if not m:
        return ""
    nxt = re.search(r"^## ", text[m.end():], re.M)
    return text[m.end(): len(text) if not nxt else m.end() + nxt.start()]


def main():
    quiet = "--quiet" in sys.argv
    problems = []
    warns = []
    infos = []

    files = scan_files()
    contents = {f: read(os.path.join(REPO, f)) for f in files}

    # 1 + 2 — fences (root docs only: technique class docs must carry commands; agent role
    # definitions under agents/ route to the class docs and are not command carriers themselves)
    for f, text in contents.items():
        n = text.count(FENCE)
        if n % 2 == 1:
            problems.append(f"UNBALANCED FENCES: {f} has an odd number of ``` markers ({n})")
        if n == 0 and not os.path.dirname(f) and f not in NO_COMMAND_DOCS:
            problems.append(f"ZERO CODE FENCES: {f} — no runnable commands (commands-first violation)")

    # 3 — wiki-links
    for f, text in contents.items():
        for name in sorted(set(re.findall(r"\[\[([a-zA-Z0-9_./-]+)\]\]", text))):
            if not link_targets_exist(name, f):
                problems.append(f"UNRESOLVED WIKI-LINK: [[{name}]] in {f}")

    # 4 — ROUTER integrity
    skill = contents.get("SKILL.md")
    router_root_refs = set()
    if skill is None:
        problems.append("ROUTER: SKILL.md not found at repo root")
    else:
        router = router_section(skill)
        refs = sorted(set(re.findall(r"[A-Za-z0-9_][A-Za-z0-9_/.-]*\.md", router)))
        for r in refs:
            if not os.path.isfile(os.path.join(REPO, r)):
                problems.append(f"ROUTER TARGET MISSING: {r} (referenced from SKILL.md ROUTER table)")
        referenced = {os.path.basename(r) for r in refs}
        # root-level docs the ROUTER wires in (path-qualified refs point outside root)
        router_root_refs = {r for r in refs if not os.path.dirname(r)}
        for f in files:
            base = os.path.basename(f)
            if os.path.dirname(f):
                continue  # orphan check is for root-level docs only
            if base in referenced or base in ORPHAN_ALLOWLIST or base in MANUAL_ONLY_DOCS \
                    or AUDIT_RE.match(base):
                continue
            problems.append(f"ORPHAN DOC: {base} — root doc not referenced by any ROUTER row")

    wh = contents.get("web-hunt.md")
    wh_refs = set()
    if wh is None:
        problems.append("WEB-HUNT: web-hunt.md not found at repo root")
    else:
        wh_refs = {os.path.basename(r)
                   for r in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_/.-]*\.md", wh)}

    # 5 — web-hunt.md class-table coverage: ROUTER-wired root docs must be visible to the hunter
    for r in sorted(router_root_refs):
        if r in WEBHUNT_ABSENT_OK or r in MANUAL_ONLY_DOCS or r in ORPHAN_ALLOWLIST \
                or AUDIT_RE.match(r):
            continue
        if wh is not None and r not in wh_refs:
            problems.append(
                f"WEB-HUNT TABLE: {r} is wired into SKILL.md's ROUTER but never referenced in "
                f"web-hunt.md — bughunter STEP 3 follows web-hunt's class table, so the hunter "
                f"never sees this class (extend WEBHUNT_ABSENT_OK only with a stated reason)")

    # 6 — MANUAL-ONLY invariant
    if skill is not None:
        sec = manual_only_section(skill)
        if sec is None:
            problems.append("MANUAL-ONLY: section heading not found in SKILL.md")
        else:
            for doc in MANUAL_ONLY_DOCS:
                stem = doc[: -len(".md")]
                outside = 0
                pos = 0
                for m in re.finditer(stem, skill):
                    if not (sec[0] <= m.start() < sec[1]):
                        outside += 1
                if outside:
                    problems.append(
                        f"MANUAL-ONLY VIOLATION: {doc} mentioned {outside}x in SKILL.md OUTSIDE "
                        f"the MANUAL-ONLY section (must appear ONLY there)")
    if wh is None:
        problems.append("MANUAL-ONLY: web-hunt.md not found")
    else:
        for doc in MANUAL_ONLY_DOCS:
            n = len(re.findall(doc[: -len(".md")], wh))
            if n:
                problems.append(f"MANUAL-ONLY VIOLATION: {doc} appears {n}x in web-hunt.md (must appear 0 times)")

    # 7 — gate substance (INFO only — see docstring: heading-presence linting would convert
    # gating into a permanent compliance checkbox; substance under other names counts)
    # Process docs (validate.md IS the gate; reporting.md assembles it) are not vuln classes.
    gateless = []
    for f, text in contents.items():
        base = os.path.basename(f)
        if os.path.dirname(f) or base in ORPHAN_ALLOWLIST or AUDIT_RE.match(base) \
                or base in ("validate.md", "reporting.md"):
            continue
        low = text.lower()
        if not any(p in low for p in GATE_SUBSTANCE) and not GATE_HEADING_RE.search(text):
            gateless.append(base)
    if gateless:
        infos.append(
            "no gate substance found (INFO, not a failure — fine if the class needs no proof bar; "
            "add a class-specific falsifier only for always-rejected/conditionally-valid classes): "
            + ", ".join(sorted(gateless)))

    # 8 — validate.md pointer rule: agent files resolve validate.md to the ROOT doc
    for f, text in contents.items():
        if os.path.dirname(f) != "agents":
            continue
        if "knowledge/bug-bounty/commands/validate.md" in text:
            problems.append(
                f"VALIDATE POINTER: {f} routes to the knowledge/bug-bounty copy of validate.md — "
                f"the gate is the ROOT validate.md (the Q8 identity check lives there); finder and "
                f"gatekeeper must grade against the same rubric")

    # 9 — agent mirror drift vs the canonical ~/.claude/agents/ (WARN, never FAIL)
    if not os.path.isdir(CANONICAL_AGENTS_DIR):
        warns.append(f"AGENTS MIRROR: canonical dir not found: {CANONICAL_AGENTS_DIR} — drift check skipped")
    else:
        for f in files:
            if os.path.dirname(f) != "agents":
                continue
            base = os.path.basename(f)
            canon = os.path.join(CANONICAL_AGENTS_DIR, base)
            if not os.path.isfile(canon):
                warns.append(f"AGENTS MIRROR: {base} has no canonical copy in ~/.claude/agents/ "
                             f"(repo-only agent, or canonical was renamed?)")
            elif contents[f] != read(canon):
                warns.append(f"AGENTS MIRROR DRIFT: agents/{base} differs from ~/.claude/agents/{base} "
                             f"(repo {len(contents[f])}B vs canonical {len(read(canon))}B) — re-mirror "
                             f"after landing, or the canonical copy silently keeps the old grants/advice")

    # report — FAILs gate; WARNs and INFOs inform
    if warns:
        print(f"check_docs.py — {len(warns)} warning(s):")
        for w in warns:
            print("  WARN:", w)
        print()
    if infos:
        for i in infos:
            print("  INFO:", i)
        print()
    if problems:
        print(f"check_docs.py — {len(problems)} problem(s):\n")
        for p in problems:
            print("  FAIL:", p)
        print("\nMeta note: root docs allowed unrouted (meta allowlist):",
              ", ".join(sorted(ORPHAN_ALLOWLIST)) + ", AUDIT-*.md;",
              "MANUAL-ONLY docs unrouted by design:", ", ".join(MANUAL_ONLY_DOCS) + ".")
        sys.exit(1)
    if not quiet:
        print(f"check_docs.py — OK: {len(files)} docs scanned "
              f"(fences balanced, wiki-links resolve, ROUTER intact, web-hunt table covers the "
              f"router, MANUAL-ONLY invariant holds: {', '.join(MANUAL_ONLY_DOCS)} absent from "
              f"web-hunt.md, agent validate.md pointers resolve to root)")
    sys.exit(0)


if __name__ == "__main__":
    main()
