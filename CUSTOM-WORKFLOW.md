# Moraa — Custom Unified Offensive Workflow (Plan)

> **Tier 2 — operator layer.** This doc describes *one* working setup, published as a
> reference rather than a requirement. Yours will differ; nothing in the methodology
> depends on it. See [CUSTOMIZATION.md](CUSTOMIZATION.md).

> Saved 2026-06-14. Owner: Amr Kadry. Engine decision: **ONE ENGINE — Claude Code only.**
> Status: building. This file is the source-of-truth plan; update it as the pack evolves.

## Decision summary

- **One engine.** Everything runs inside Claude Code (Opus 4.8). PentesterFlow is **not**
  installed and is **not** a runtime. We only borrow its *design ideas*.
- **Merge target:** a single skill pack `moraa-ai-offsec-agent/` that fuses:
  - `claude-bug-bounty` — web/external methodology, vuln-class tables, 7-Question validation gate.
  - `claude-red` (62 `offensive-*` skills) — AD, lateral movement, exploit-dev, reporting.
  - **Ideas** lifted from PentesterFlow — engagement folder, single `auth.json`, coverage
    matrix, findings store, continuous-learning notes, curl-first "no theoretical bugs" rule.
- **New content written from scratch** (gaps none of the three cover well): **pivoting/tunneling**
  (the #1 weak area — claude-red has NO dedicated pivot skill), **Windows privesc**, **Linux
  privesc**, and the connective tissue that turns a web foothold into an internal AD compromise.
- **Windows-native.** No bash install scripts, no `fcntl`. Attacker commands target Kali/WSL
  (CPTS exam reality); Claude Code itself drives from Windows.

## Architecture (one engine)

```
YOU (Windows 11) ── Claude Code / Opus 4.8 ──┬─ moraa-ai-offsec-agent SKILL.md (router + engagement model)
                                             ├─ phase docs (recon, web-hunt, pivoting, AD, privesc…)
                                             ├─ engagements/<target>/  (scope + auth.json + findings)
                                             └─ shells out to Kali/WSL for tools
```

Claude is strategist **and** executor. State lives in the engagement folder, not in a separate
program.

## Engagement model (single source of truth)

```
engagements/<target>/
  ENGAGEMENT.md     # scope, rules of engagement, authorization note, crown jewels
  auth.json         # cookies / bearer / headers / creds / scope   ← you fill once
  docs/             # drop program policy, PDFs, API specs, BloodHound zips here
  findings/         # one <slug>.md per confirmed finding (evidence-backed)
  coverage.md       # what endpoints/hosts/vuln-classes are tested  (the /next driver)
  recon/ loot/ pivot/   # tool output, dumps, tunnel notes
  report/           # final deliverable assembled from findings/
```

## Easy auth input — `auth.json` (the explicit ask)

```json
{
  "scope":   ["*.target.com", "10.10.10.0/24"],
  "cookie":  "session=PASTE_HERE",
  "bearer":  "eyJ...",
  "headers": ["X-Org-Id: 42"],
  "creds":   [{"user":"low","pass":"...","role":"attacker"},
              {"user":"admin","pass":"...","role":"victim"}],
  "docs":    "docs/"
}
```

Fill it once. The master skill reads it, sets scope, loads the two creds for dual-session IDOR
testing, and ingests anything in `docs/`. Secrets stay local; never pasted into reports.

## The merged phase flow

| # | Phase | Track | moraa-ai-offsec-agent doc | Source |
|---|---|---|---|---|
| 0 | Scope + auth | both | `SKILL.md` (engage) | new (PF idea) |
| 1 | Recon | both | `recon.md` | bug-bounty + claude-red |
| 2 | Web hunt | external | `web-hunt.md` | bug-bounty vuln tables + A→B chains |
| 3 | Foothold → internal | internal | `initial-access.md` | claude-red initial-access |
| 4 | **Pivoting / tunneling** | internal | `pivoting.md` | **new — ligolo-ng first** |
| 5 | AD enum + paths | internal | `active-directory.md` | claude-red AD |
| 6 | **Privesc (Win/Linux)** | internal | `privesc-windows.md` / `privesc-linux.md` | **new** |
| 7 | Lateral movement | internal | `lateral-movement.md` | claude-red AD |
| 8 | Validate | both | `validate.md` | bug-bounty 7-Question Gate |
| 9 | Report | both | `reporting.md` | bug-bounty + claude-red reporting |
| 10 | Learn | both | `coverage.md` per engagement | PF continuous-learning idea |

## Build order / status — COMPLETE (v1, 2026-06-14)

- [x] Save this plan
- [x] `SKILL.md` master router + engagement model + auth loader
- [x] `auth.example.json` + `engagements/_TEMPLATE/` (ENGAGEMENT.md + coverage.md)
- [x] `pivoting.md`  (gap #1 — ligolo-ng first)
- [x] `privesc-windows.md` / `privesc-linux.md`  (gap #2)
- [x] `active-directory.md`  (orchestrates claude-red AD)
- [x] `validate.md`  (7-Question Gate)
- [x] `reporting.md`  (CPTS report + H1/Bugcrowd templates)
- [x] `web-hunt.md` + `recon.md`  (route to bug-bounty depth)
- [x] `initial-access.md` + `lateral-movement.md`

### v2 status
- [x] `engage.ps1` — scaffolds `engagements/<target>/` from `_TEMPLATE` (Windows-native, tested 2026-06-14).
      Usage: `pwsh .\engage.ps1 <target> [-Base <dir>]`
- [ ] Payload snippet files under `moraa-ai-offsec-agent/payloads/`.
- [ ] Pull the deep bypass tables inline if the old packs are ever removed from disk.

## Design rules

1. **Commands first, prose second** (matches owner's CLAUDE.md exam mode).
2. **No theoretical bugs** — every finding needs a real PoC + concrete impact (bug-bounty rule).
3. **Set up the pivot BEFORE going deeper** (owner's standing instruction).
4. **One finding = one file in `findings/`** with request/response evidence.
5. **Windows-safe**: Claude drives from Windows; attack tooling runs in Kali/WSL.
