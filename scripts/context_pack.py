#!/usr/bin/env python3
"""
context_pack.py — distil an engagement into a brief an agent can actually use.

WHY: coverage.md grows to thousands of lines. An agent handed only a target
re-treads closed ground; an agent handed the whole file drowns. This emits a
~1-2 page pack: what is confirmed, what is a lead, what is CLOSED (and must not
be re-proposed), what was KILLED at the validation gate (do not re-propose
without the new evidence named in the file), what is a CLEAN NEGATIVE (already
tested, control verified), what was retracted (and why), and the open credential
blockers.

The "do not re-propose" list is the important part. It is built from the
findings/ files themselves — never from a summary line — because summary lines
go stale and finding files do not. Every verdict is durable: KILL-<slug>.md and
CLEAN-<slug>.md files (see validate.md § "Every verdict gets a file") are what
stop a killed or cleanly-negatived lead from being re-proposed next run.
In-progress `findings/<slug>.candidate.md` files are deliberately skipped — a
candidate is not a verdict.

Usage:
  python3 context_pack.py <engagement_dir> [--host <host>]   # optional focus
"""
import os
import sys

# Windows consoles default to cp1252; this script emits non-ASCII status glyphs.
# Reconfigure rather than strip them, so output is identical on every platform.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import re
import sys

CLOSED_KW = ("DISPROVEN", "RETRACTED", "NOT RUN", "CLOSED AS INFORMATIONAL",
             "REMEDIATED", "NO LONGER REPRODUCIBLE", "CLOSED, CORE HYPOTHESIS NEGATIVE")


def read(p):
    with open(p, encoding="utf-8", errors="ignore") as f:
        return f.read()


def field(text, *names):
    for n in names:
        m = re.search(r"^[-*\s]*\*{0,2}" + n + r"\*{0,2}\s*:?\**\s*:?\s*(.+)$",
                      text, re.M | re.I)
        if m:
            return re.sub(r"\s+", " ", m.group(1).strip().strip("*"))[:200]
    return ""


def title(text, fname):
    m = re.search(r"^#\s+(.+)$", text, re.M)
    return re.sub(r"\s+", " ", (m.group(1) if m else fname)).strip()[:120]


# --- scope-driven host matching (configurable; no target is baked into this tool) ---
# Set MORAA_SCOPE_TLDS to a comma-separated list of the apex domains in scope,
# e.g.  export MORAA_SCOPE_TLDS="target.com,target-cdn.net"
# With it unset the pattern is permissive: any dotted hostname with a 2-24 char TLD.
def _scope_host_re():
    tlds = [t.strip() for t in os.environ.get("MORAA_SCOPE_TLDS", "").split(",") if t.strip()]
    if tlds:
        alt = "|".join(re.escape(t) for t in tlds)
        return re.compile(r"([a-z0-9][a-z0-9.-]*\.(?:" + alt + r"))", re.I)
    return re.compile(r"([a-z0-9][a-z0-9.-]*\.[a-z]{2,24})", re.I)


SCOPE_HOST_RE = _scope_host_re()


def host_of(text):
    # The leading `[-*\s]*` is load-bearing: every finding file in this library
    # writes the asset as a markdown list item (`- Asset: host`). Without it the
    # Asset line never matched and host_of fell through to scanning the header
    # region, returning whichever *.acme.example host appeared FIRST there - often one
    # merely MENTIONED in the title. A lead titled "... not account.acme.example" was
    # filed under account.acme.example, so `--host mesh.svc.acme.example` dropped it and
    # the verdict vanished from the pack: a durable finding that silently stopped
    # compounding, which is the one failure this script exists to prevent.
    m = re.search(r"^[-*\s]*\*{0,2}Asset:?\*{0,2}\s*:?\s*(.+)$", text, re.M | re.I)
    # try the Asset: line first, then fall back to the header region — an Asset
    # line that names no parseable host must not collapse the record to "?"
    for src in ([m.group(1)] if m else []) + [text[:1500]]:
        for h in SCOPE_HOST_RE.findall(src):
            if (not h.split(".")[0].isdigit()
                    and h.lower() not in ("acme.example", "acme-legacy.example", "acme-nms.example", "svc.acme.example")):
                return h.lower()
    return "?"


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    eng = sys.argv[1]
    focus = None
    if "--host" in sys.argv:
        focus = sys.argv[sys.argv.index("--host") + 1].lower()
    if not os.path.isdir(eng):
        sys.exit("no such engagement dir: %s" % eng)
    fdir = os.path.join(eng, "findings")
    target = os.path.basename(os.path.normpath(eng))

    # A freshly scaffolded engagement has no findings/ yet (it is gitignored, so
    # _TEMPLATE ships without it). That is the normal first-run state, not an error:
    # emit an empty pack so the very first `context_pack.py` call still works.
    entries = sorted(os.listdir(fdir)) if os.path.isdir(fdir) else []

    confirmed, leads, closed, killed, clean = [], [], [], [], []
    for fn in entries:
        if not fn.endswith(".md") or fn.endswith(".candidate.md"):
            continue  # candidate = handoff artifact awaiting a verdict, not a verdict
        t = read(os.path.join(fdir, fn))
        h = host_of(t)
        if focus and focus not in h and focus not in fn.lower():
            continue
        head = t[:1200].upper()
        if fn.upper().startswith("KILL-"):
            # kill reason + re-open condition are the whole point of the file — surface them
            killed.append((h, title(t, fn), fn, field(t, "Killed by"), field(t, "Re-open when")))
        elif fn.upper().startswith("CLEAN-"):
            clean.append((h, title(t, fn), fn, field(t, "Control"), field(t, "Control result")))
        else:
            rec = (h, title(t, fn), fn, field(t, "Status") or field(t, "Severity"))
            if any(k in head or k in rec[1].upper() for k in CLOSED_KW):
                closed.append(rec)
            elif fn.upper().startswith("LEAD-"):
                leads.append(rec)
            else:
                confirmed.append(rec)

    out = [f"# Context pack — {target}" + (f" (focus: {focus})" if focus else ""), ""]
    out += ["**Read this before proposing any work.** Every line below comes from a "
            "`findings/` file, not a summary — summary lines go stale, finding files do not.", ""]

    out += [f"## CLOSED — do NOT re-test or re-propose ({len(closed)})", ""]
    for h, ti, fn, st in sorted(closed):
        out.append(f"- `{h}` — {ti}")
        if st:
            out.append(f"  - status: {st}")
        out.append(f"  - source: `findings/{fn}`")
    out.append("")

    out += [f"## KILLED — do not re-propose without new evidence ({len(killed)})", ""]
    for h, ti, fn, why, reopen in sorted(killed):
        out.append(f"- `{h}` — {ti}")
        if why:
            out.append(f"  - killed by: {why}")
        if reopen:
            out.append(f"  - re-open when: {reopen}")
        out.append(f"  - source: `findings/{fn}`")
    out.append("")

    out += [f"## CLEAN NEGATIVE — already tested ({len(clean)})", ""]
    for h, ti, fn, ctrl, result in sorted(clean):
        out.append(f"- `{h}` — {ti}")
        if ctrl:
            out.append(f"  - control: {ctrl}" + (f" → {result}" if result else ""))
        out.append(f"  - source: `findings/{fn}`")
    out.append("")

    out += [f"## CONFIRMED findings ({len(confirmed)})", ""]
    for h, ti, fn, st in sorted(confirmed):
        out.append(f"- `{h}` — {ti}" + (f" _({st})_" if st else ""))
    out.append("")

    out += [f"## OPEN leads — unproven, need work ({len(leads)})", ""]
    for h, ti, fn, st in sorted(leads):
        out.append(f"- `{h}` — {ti}")
        out.append(f"  - source: `findings/{fn}`")
    out.append("")

    # credential / access blockers, mined from coverage.md
    cov = os.path.join(eng, "coverage.md")
    if os.path.isfile(cov):
        blockers = []
        for ln in read(cov).split("\n"):
            if re.search(r"blocked on|needs? (a |an )?(second|valid|live|real)|"
                         r"credential|no account|requires? a human|captcha", ln, re.I):
                s = ln.strip("-*| ").strip()
                if 40 < len(s) < 240:
                    blockers.append(s)
        if blockers:
            out += ["## Known blockers (from coverage.md)", ""]
            for b in blockers[:12]:
                out.append(f"- {b}")
            out.append("")

    out += ["## Standing reminders", "",
            "- A stale `coverage.md` line is not evidence. Re-read the `findings/` file.",
            "- Leads are not findings. Do not submit from a lead.",
            "- A KILL re-opens only on the new evidence named in its file — not on a hunch.",
            "- Two accounts minimum for any authz test. Never reuse one session across roles.",
            "- Read-only against production; no state-changing write to prove a bug.", ""]

    print("\n".join(out))


if __name__ == "__main__":
    main()
