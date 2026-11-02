# Moraa — Reporting

> Two modes: **pentest/CPTS report** (one deliverable, full engagement) and **bug-bounty
> submission** (one report per finding/chain). Assemble from `findings/`. Start Day 1.
> Deep reference: `knowledge/offensive/offensive-reporting.md`. Web templates: `knowledge/bug-bounty/SKILL.md`.

---

## CPTS / Pentest report structure

```
report/
  00-executive-summary.md     # non-technical: risk story, business impact, overall posture
  01-scope-methodology.md     # scope, rules of engagement, dates, approach, limitations
  02-findings/                # one per finding, severity-ordered (critical → low)
  03-attack-narrative.md      # the chain: how you went from foothold → DA, step by step
  04-remediation-summary.md   # prioritized fix list
  05-appendix.md              # tool output, command log, full host list
```

### Executive summary (write LAST, read FIRST)
- 3-5 short paragraphs, no jargon. What you were asked to do, what you found, what it means for
  the business, the single most important thing to fix.
- Lead with risk, not vuln names. "An attacker on the internal network could reach Domain Admin
  within hours" beats "Kerberoasting was possible."

### Finding format (technical section)

```markdown
## [Severity] Title — class in location → impact
**Affected:** <host/url/scope>   **CVSS:** x.x (vector)  [web]   /  **Risk:** High [internal]

### Description
What it is, root cause, where. Plain language for a smart dev/admin.

### Steps to Reproduce
1. exact command / request (copy-paste)
2. ...
### Evidence
<request + response excerpt / screenshot ref / command output, timestamped>
### Impact
What the attacker gains, who/what is affected, quantified.
### Remediation
1-2 concrete sentences.
### References
CWE / MITRE ATT&CK / vendor docs
```

### Attack narrative (the CPTS differentiator)
A chronological story chaining findings: external foothold → pivot → first creds → BloodHound
path → escalation → DA. Each step = what you did, the command, the result, the next door it
opened. This is what proves you actually compromised the environment.

---

## Bug-bounty submission (H1 / Bugcrowd)

```
Title: [Class] in [exact endpoint] allows [actor] to [impact] [victim scope]

## Summary        (2-3 sentences: what, where, what attacker can do)
## Steps To Reproduce   (copy-paste HTTP request, two accounts if access-control)
## Supporting Material  (screenshot/Burp request-response showing real impact)
## Impact          (specific harm, quantified: "affects all X users")
## Severity        CVSS 3.1 x.x — vector
## Remediation     (1-2 sentences)
```

60-second pre-submit: title follows formula · first sentence = impact in plain English · exact
request included · response proving the bug · two accounts used · CVSS matches impact (don't
overclaim) · no endpoint typos · < 600 words · fix is one sentence.

---

## CVSS 4.0 (newer programs — 3.1 quick reference lives in `validate.md`)

CVSS 4.0 replaced 3.1 in Nov 2023; some newer programs now require it. Key deltas from 3.1:

| Metric | 3.1 | 4.0 |
|---|---|---|
| Scope (S) | Unchanged/Changed | **removed** |
| Attack Requirements (AT) | didn't exist | **new** — None/Present (race or specific config needed) |
| User Interaction (UI) | None/Required | None/**Passive**(victim visits URL)/**Active**(explicit action) |
| Impact | single C/I/A triad | **split**: Vulnerable-system (VC/VI/VA) + Subsequent-system (SC/SI/SA) downstream impact |

```
Unauthenticated RCE          10.0  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
IDOR read PII, auth required  6.9  CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
Stored XSS, admin views it    8.2  CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N
SSRF → cloud metadata         8.7  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N
```

Don't hand-derive the vector — use https://www.first.org/cvss/calculator/4.0 and paste the full
`CVSS:4.0/...` string. Programs can't dispute a valid vector string the way they can a bare number.

---

## Mid-engagement IR observation (red-team/internal — client SOC is live during your test)

On a monitored engagement, the target's security state is **not static** — it changes in response
to your traffic. When a confirmed finding stops reproducing mid-engagement, that's data, not a
retraction trigger.

**Capture before, diff after.** At session start, snapshot per key target: baseline response
time/size, response headers, WAF cookies present, lockout/error counters. Log every test to an
append-only JSONL. On first failed recheck, re-snapshot and diff. A significant delta (new WAF
cookie, timing reverted to baseline, new 403/429/406 on the exact payload) means a mitigation
deployed — investigate the delta, don't discard the finding:
1. **Original PoC artifacts are forever** — the request/response/timing you captured at T0 remains
   the vulnerability finding regardless of what happens at T0+30min.
2. **Try 2-3 WAF-evasion variants** (re-encode the payload, swap method/content-type, slower pace)
   before declaring the signal gone. If evasion restores it → WAF-layer mitigation (bypassable,
   say so). If nothing restores it → likely a code-level fix (durable).
3. **Document both states**: "vulnerable at T0 via <PoC>, mitigation observed at T0+<delta>,
   depth: [WAF|code]." This is a stronger deliverable than "confirmed SQLi" alone — it proves the
   bug **and** the client's IR responsiveness.

**Active-concurrent-attacker signal** (credential-spray engagements — see
`credential-access.md`/`m365-entra-attack.md`): if you're seeing far more lockouts than your own
1-attempt-per-user discipline could cause, do the math (your journal proves N attempts/user) and
report the excess as a live external attacker, not your own noise. Cluster locked accounts
alphabetically (sorted-wordlist spray signature) and diff lockout count before/after your session
— new locks accumulating *during* your window is the strongest tell. This is often the single
highest-value finding on a credential engagement.

**Never do:** "recheck failed so it was a false positive" (investigate the delta first) · "they
patched it, drop the finding" (the finding stays, add a mitigated-state note) · omit the observed
IR response from the deliverable (it's a positive finding for the client, include it).

---

## Writing rules (avoid AI-sounding, avoid triager friction)

- Start sentences with the impact, not the vuln name.
- Active voice, "I found that…", concrete over abstract.
- No em dashes, avoid "comprehensive/leverage/seamless/robust/ensure".
- One real example beats three abstract sentences.
- Don't undermine your own severity; don't pad length.

## Severity escalation counters (when downgraded)

| They say | You counter |
|---|---|
| "Requires auth" | "Only a free account, no special role" |
| "Limited impact" | "Affects N users / this PII / $X" |
| "Already known" | "Give me the report # — I searched, found none" |
| "By design" | "Show the doc that says this is intended" |
| "Low CVSS" | "CVSS misses business impact — attacker steals X" |

---

## Evidence hygiene (both modes)

- Timestamp every action (CPTS requires it).
- Redact credentials/tokens/PII in the deliverable; keep raw in local `loot/` only.
- Hash/sample client data rather than dumping it wholesale.
- Keep a command log (`05-appendix.md`) so any finding is reproducible.

Assemble: read all `findings/*.md` → order by severity → write technical sections → write the
attack narrative from `pivot/` + `loot/` notes → write exec summary last → remediation summary.

---

# Notion documentation — DEFAULT final step

Generate, never hand-build:

```bash
python3 ~/.claude/skills/moraa-ai-offsec-agent/scripts/notion_export.py "engagements/<target>"
# -> engagements/<target>/notion/notion_manifest.json   (tree -> feed the Notion MCP)
# -> engagements/<target>/notion/pages/**.md            (one file per page)
```

## Structure

```text
<Target> — Bug Bounty
│
├── Summary
│   ├── Scope
│   ├── Statistics
│   └── Severity Overview
│
├── Coverage
│   ├── Tested Assets
│   ├── Untested Assets
│   └── Coverage Notes
│
├── Assets
│   ├── <host>
│   │   ├── Finding 001 — <title>
│   │   │   └── PoC
│   │   └── ...
│   └── _unsorted
│
├── Leads
│   └── Lead 001 — <title>
│
└── Archive
```

## Page templates

**Asset** — `Overview` (Status / Priority / Tested / Findings) · `Findings` (list) · `Notes` (short).

**Finding** — `Metadata` (Asset / Severity / Status / Type / Discovered / Researcher) ·
`Impact` (2–4 sentences) · `Description` · `Reproduction` · `Evidence` · `PoC` (→ subpage) · `Notes`.

**PoC** — `Prerequisites` · `Request` · `Response` · `Reproduction` (curl) · `Result` · `Evidence`.

**Lead** — Asset / Source / Hypothesis / Current status · `Notes` · `Next Steps`
(`[ ] Validate` `[ ] Reproduce` `[ ] Determine impact` `[ ] Convert to finding`).

## Rules

- One engagement → one root page.
- One subdomain/asset → one subpage.
- One confirmed finding → one finding page. One PoC → one PoC subpage.
- **Leads stay out of Assets.** Separate top-level section.
- **Closed / disproven / retracted / process docs → `Archive`.** Not findings, not leads,
  excluded from counts. A disproven lead rendered as "Finding NNN" is the failure mode these
  rules exist to prevent.
- **No invented assets.** No hostname in the header region → `_unsorted`. Never guess from the
  filename; date-shaped labels (`2026.acme.example`) and bare zone apexes (`svc.acme.example`) are rejected.
- No duplicate findings (deduped on normalised title).
- Keep summaries short. Raw technical evidence belongs on the PoC page.
- Unknown metadata → empty field. Never fabricate.
- Idempotent — re-run every session so the tree never drifts from `findings/`.

## Publishing

Walk `notion_manifest.json` depth-first; create a page per node with its `file` as the body; push
in one pass so parent IDs exist for children. **If the Notion tools are not loadable, hand over the
bundle path and say plainly it was not published.**

## Workflow

```text
Hunt → Asset → Finding or Lead → Evidence → PoC → Validate → Notion
```
