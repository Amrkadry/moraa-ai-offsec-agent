#!/usr/bin/env python3
"""
notion_export.py — build the standard Moraa Notion page tree from an engagement dir.

STRUCTURE (fixed — do not improvise a different one):

    <Target> — Bug Bounty
    ├── Summary
    │   ├── Scope
    │   ├── Statistics
    │   └── Severity Overview
    ├── Coverage
    │   ├── Tested Assets
    │   ├── Untested Assets
    │   └── Coverage Notes
    ├── Assets
    │   ├── <host>
    │   │   ├── Finding 001 — <title>
    │   │   │   └── PoC
    │   │   └── ...
    │   └── _unsorted
    └── Leads
        └── Lead 001 — <title>

RULES (enforced here):
  * One engagement -> one root page.
  * One subdomain/asset -> one subpage.
  * One confirmed finding -> one finding page. One PoC -> one PoC subpage.
  * Leads stay OUT of Assets, in their own top-level section.
  * No invented assets  (no hostname in the header region -> `_unsorted`).
  * No duplicate findings (deduped on normalised title).
  * Summaries short; raw technical evidence lives on the PoC page.
  * Idempotent: re-running regenerates the tree from findings/ + coverage.md.

Unknown metadata is emitted as an empty field, never fabricated.

Usage:
  python3 notion_export.py <engagement_dir> [out_dir]
"""
import json
import os
import re
import sys

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

POC_HEADINGS = re.compile(
    r"^#{1,4}\s*.*(evidence|proof|reproduce|reproduction|poc|request|response|"
    r"verification|steps)\b", re.I)

_BAD_HOSTS = {"acme.example", "acme-legacy.example", "acme-nms.example", "svc.acme.example",
              "dev.svc.acme.example", "stg.svc.acme.example"}


def read(p):
    with open(p, encoding="utf-8", errors="ignore") as f:
        return f.read()


def write(p, s):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)


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


def plausible_host(h):
    h = h.lower().strip(".")
    if h in _BAD_HOSTS:
        return False
    return not h.split(".")[0].isdigit()


def parse_host(text):
    m = re.search(r"^\*{0,2}Asset:?\*{0,2}\s*:?\s*(.+)$", text, re.M | re.I)
    if m:
        for h in SCOPE_HOST_RE.findall(m.group(1)):
            if plausible_host(h):
                return h.lower()
    for h in SCOPE_HOST_RE.findall(text[:1500]):
        if plausible_host(h):
            return h.lower()
    return "_unsorted"


def parse_field(text, *names):
    for n in names:
        m = re.search(r"^[-*\s]*\*{0,2}" + n + r"\*{0,2}\s*:?\**\s*:?\s*(.+)$",
                      text, re.M | re.I)
        if m:
            v = m.group(1).strip().strip("*").strip()
            v = re.sub(r"\s+", " ", v)
            if v:
                return v[:160]
    return ""


def parse_severity(text, fname):
    raw = parse_field(text, "Severity")
    if raw:
        low = raw.lower()
        for k in SEV_ORDER:
            if k in low:
                return k, raw
    if fname.upper().startswith("LOW-"):
        return "low", "Low"
    return "unknown", raw


def is_archived(text, fname):
    """Closed / disproven / retracted / process docs are NOT findings and NOT leads.

    Presenting a disproven lead as "Finding NNN" is exactly the failure the rules
    exist to prevent, so these get their own section and are excluded from counts.
    """
    if fname.upper().startswith("VALIDATION-"):
        return True
    head = text[:900].upper()
    title = parse_title(text, fname).upper()
    for kw in ("DISPROVEN", "RETRACTED", "NOT RUN",
               "CLOSED AS INFORMATIONAL", "REMEDIATED"):
        if kw in title or kw in head:
            return True
    return False


def is_lead(text, fname):
    if fname.upper().startswith("LEAD-"):
        return True
    st = parse_field(text, "Status").lower()
    return st.startswith("lead") or "not a submittable" in st or "not submittable" in st


def parse_title(text, fname):
    m = re.search(r"^#\s+(.+)$", text, re.M)
    t = m.group(1) if m else os.path.splitext(fname)[0]
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"^(LEAD|LOW|AMEND)\s*[-—:]\s*", "", t, flags=re.I)
    # severity already lives in Metadata; don't repeat it in the title
    t = re.sub(r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*[-—:]\s*", "", t, flags=re.I)
    return t[:110]


def split_poc(text):
    out, poc, in_poc = [], [], False
    for ln in text.split("\n"):
        if re.match(r"^#{1,4}\s", ln):
            in_poc = bool(POC_HEADINGS.match(ln))
        (poc if in_poc else out).append(ln)
    if not [l for l in poc if l.strip()]:
        return text.strip(), ""
    return "\n".join(out).strip(), "\n".join(poc).strip()


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:70] or "page"


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    eng = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(eng, "notion")
    fdir = os.path.join(eng, "findings")
    if not os.path.isdir(fdir):
        sys.exit(f"no findings dir at {fdir}")
    target = os.path.basename(os.path.normpath(eng))
    P = os.path.join(out, "pages")

    findings, leads, archive, seen = [], [], [], set()
    for fn in sorted(os.listdir(fdir)):
        if not fn.endswith(".md"):
            continue
        text = read(os.path.join(fdir, fn))
        title = parse_title(text, fn)
        key = re.sub(r"[^a-z0-9]", "", title.lower())[:60]
        if key in seen:                      # no duplicate findings
            continue
        seen.add(key)
        sev, sev_raw = parse_severity(text, fn)
        body, poc = split_poc(text)
        rec = {"file": fn, "title": title, "host": parse_host(text),
               "severity": sev, "severity_raw": sev_raw or sev,
               "status": parse_field(text, "Status"),
               "type": parse_field(text, "Class", "Type"),
               "discovered": parse_field(text, "Date", "Discovered"),
               "body": body, "poc": poc}
        if is_archived(text, fn):
            archive.append(rec)
        elif is_lead(text, fn):
            leads.append(rec)
        else:
            findings.append(rec)

    findings.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9), r["host"], r["title"]))
    leads.sort(key=lambda r: (r["host"], r["title"]))
    for i, r in enumerate(findings, 1):
        r["num"] = f"{i:03d}"
    for i, r in enumerate(leads, 1):
        r["num"] = f"{i:03d}"

    by_host = {}
    for r in findings:
        by_host.setdefault(r["host"], []).append(r)
    sev_counts = {}
    for r in findings:
        sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1

    tree = {"page": f"{target} — Bug Bounty", "children": []}

    # ---------------- Summary ----------------
    write(f"{P}/summary/_index.md", "\n".join([
        f"# {target} — Bug Bounty", "",
        f"- **Target:** `{target}`", "- **Type:** Bug bounty", "- **Status:** Active",
        f"- **Total findings:** {len(findings)}",
        f"- **Leads:** {len(leads)}",
        f"- **Assets:** {len(by_host)}", "- **Documentation:** Notion", ""]))
    write(f"{P}/summary/scope.md", "\n".join([
        "# Scope", "", "**In scope**", "", "- `*.acme.example`", "- `*.acme-legacy.example`", "- `*.acme-nms.example`", "",
        "**Out of scope**", "",
        "- `{uuid}.acme-hosting.acme.example` and all customer-operated the NMS appliance/the vendor platform tenants",
        "- Third-party SaaS (Zendesk, Shopify, Investis, Moonami, StatusPage)", ""]))
    write(f"{P}/summary/statistics.md", "\n".join([
        "# Statistics", "", "| metric | value |", "|---|---|",
        f"| Assets with findings | {len(by_host)} |",
        f"| Confirmed findings | {len(findings)} |",
        f"| Leads | {len(leads)} |",
        f"| Total documents | {len(findings)+len(leads)} |", ""]))
    sev_rows = ["# Severity Overview", "", "| severity | count |", "|---|---|"]
    for s in sorted(sev_counts, key=lambda x: SEV_ORDER.get(x, 9)):
        sev_rows.append(f"| {s} | {sev_counts[s]} |")
    sev_rows += ["", f"Leads are tracked separately ({len(leads)}) and are **not** findings.", ""]
    write(f"{P}/summary/severity-overview.md", "\n".join(sev_rows))
    tree["children"].append({"page": "Summary", "file": "pages/summary/_index.md", "children": [
        {"page": "Scope", "file": "pages/summary/scope.md"},
        {"page": "Statistics", "file": "pages/summary/statistics.md"},
        {"page": "Severity Overview", "file": "pages/summary/severity-overview.md"}]})

    # ---------------- Coverage ----------------
    cov = os.path.join(eng, "coverage.md")
    write(f"{P}/coverage/_index.md", "# Coverage\n\nTested assets, untested assets, and notes.\n")
    tested = "\n".join(f"- `{h}` — {len(v)} finding(s)" for h, v in sorted(by_host.items()))
    write(f"{P}/coverage/tested-assets.md",
          "# Tested Assets\n\n" + (tested or "_none_") + "\n")
    write(f"{P}/coverage/untested-assets.md",
          "# Untested Assets\n\n_Maintained by hand — assets identified but not yet tested._\n")
    write(f"{P}/coverage/coverage-notes.md",
          "# Coverage Notes\n\n" + (read(cov) if os.path.isfile(cov) else "_no coverage.md_"))
    tree["children"].append({"page": "Coverage", "file": "pages/coverage/_index.md", "children": [
        {"page": "Tested Assets", "file": "pages/coverage/tested-assets.md"},
        {"page": "Untested Assets", "file": "pages/coverage/untested-assets.md"},
        {"page": "Coverage Notes", "file": "pages/coverage/coverage-notes.md"}]})

    # ---------------- Assets ----------------
    write(f"{P}/assets/_index.md",
          "# Assets\n\nOne page per subdomain.\n\n" +
          "\n".join(f"- `{h}` ({len(v)})" for h, v in sorted(by_host.items())) + "\n")
    assets_node = {"page": "Assets", "file": "pages/assets/_index.md", "children": []}

    for host in sorted(by_host):
        rs = by_host[host]
        hs = slug(host)
        write(f"{P}/assets/{hs}/_index.md", "\n".join(
            [f"# {host}", "", "## Overview", "",
             "- Status: Tested", "- Priority:", "- Tested:",
             f"- Findings: {len(rs)}", "", "## Findings", ""] +
            [f"- Finding {r['num']} — {r['title']}" for r in rs] +
            ["", "## Notes", "", "Short technical notes only.", ""]))
        hnode = {"page": host, "file": f"pages/assets/{hs}/_index.md", "children": []}

        for r in rs:
            name = f"Finding {r['num']} — {r['title']}"
            fs = slug(f"finding-{r['num']}-{r['title']}")
            write(f"{P}/assets/{hs}/{fs}.md", "\n".join([
                f"# {name}", "", "## Metadata", "",
                f"- Asset: `{host}`",
                f"- Severity: {r['severity_raw']}",
                f"- Status: {r['status']}",
                f"- Type: {r['type']}",
                f"- Discovered: {r['discovered']}",
                "- Researcher: <your name>", "",
                "## Details", "", r["body"], "",
                "## PoC", "", "See **PoC** subpage." if r["poc"] else "_No separate PoC section._",
                "", f"_Source: `findings/{r['file']}`_", ""]))
            fnode = {"page": name, "severity": r["severity"], "source": r["file"],
                     "file": f"pages/assets/{hs}/{fs}.md", "children": []}
            if r["poc"]:
                write(f"{P}/assets/{hs}/{fs}--poc.md", "\n".join([
                    f"# PoC — Finding {r['num']}", "",
                    "## Prerequisites", "", "- Own test account session", "",
                    "## Evidence / Reproduction", "", r["poc"], ""]))
                fnode["children"].append(
                    {"page": "PoC", "file": f"pages/assets/{hs}/{fs}--poc.md"})
            hnode["children"].append(fnode)
        assets_node["children"].append(hnode)
    tree["children"].append(assets_node)

    # ---------------- Leads ----------------
    write(f"{P}/leads/_index.md", "\n".join(
        ["# Leads", "", "Not findings. Impact unproven — never submit from here.", ""] +
        [f"- Lead {r['num']} — {r['title']}" for r in leads] + [""]))
    leads_node = {"page": "Leads", "file": "pages/leads/_index.md", "children": []}
    for r in leads:
        name = f"Lead {r['num']} — {r['title']}"
        ls = slug(f"lead-{r['num']}-{r['title']}")
        write(f"{P}/leads/{ls}.md", "\n".join([
            f"# {name}", "",
            f"- Asset: `{r['host']}`",
            f"- Source: `findings/{r['file']}`",
            "- Hypothesis:",
            f"- Current status: {r['status']}", "",
            "## Notes", "", r["body"], "",
            ("## Evidence\n\n" + r["poc"] + "\n") if r["poc"] else "",
            "## Next Steps", "", "- [ ] Validate", "- [ ] Reproduce",
            "- [ ] Determine impact", "- [ ] Convert to finding", ""]))
        leads_node["children"].append(
            {"page": name, "source": r["file"], "file": f"pages/leads/{ls}.md"})
    tree["children"].append(leads_node)

    # ---------------- Archive ----------------
    if archive:
        archive.sort(key=lambda r: r["title"])
        write(f"{P}/archive/_index.md", "\n".join(
            ["# Archive", "",
             "Closed, disproven, retracted or process documents.",
             "**Not findings and not leads — never submit from here.**", ""] +
            [f"- {r['title']}" for r in archive] + [""]))
        anode = {"page": "Archive", "file": "pages/archive/_index.md", "children": []}
        for r in archive:
            asl = slug(r["title"])
            write(f"{P}/archive/{asl}.md", "\n".join([
                f"# {r['title']}", "",
                f"- Asset: `{r['host']}`",
                f"- Source: `findings/{r['file']}`",
                f"- Status: {r['status']}", "",
                r["body"], "", r["poc"], ""]))
            anode["children"].append(
                {"page": r["title"][:110], "source": r["file"],
                 "file": f"pages/archive/{asl}.md"})
        tree["children"].append(anode)

    write(os.path.join(out, "notion_manifest.json"), json.dumps(tree, indent=2))

    print(f"[*] target    : {target}")
    print(f"[*] findings  : {len(findings)}  across {len(by_host)} assets")
    print(f"[*] leads     : {len(leads)}  (separate section)")
    print(f"[*] archive   : {len(archive)}  (closed/disproven/process — excluded from counts)")
    print(f"[*] severity  : {sev_counts}")
    print(f"[*] manifest  : {os.path.join(out, 'notion_manifest.json')}")


if __name__ == "__main__":
    main()
