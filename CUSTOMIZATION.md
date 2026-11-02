# Customization — what is portable, and what is one operator's setup

This repo contains two different kinds of file, and telling them apart saves you from inheriting
someone else's toolchain.

- **Tier 1 — Portable methodology.** The actual product. Target-agnostic, operator-agnostic,
  engine-agnostic. Clone it and it works. Do not expect to edit these.
- **Tier 2 — Operator layer.** *One* working setup, published as a reference implementation rather
  than a requirement. Every doc here answers "how do **I** wire this up", and your answer will
  differ. Swap these freely; nothing in Tier 1 depends on them.
- **Tier 3 — Not published.** Listed so you know what is deliberately absent and why.

Everything is in one flat directory because `SKILL.md`'s router and the wiki-link graph
resolve against the repo root. The tier is a property of the file's content, not its path — which
is exactly what this document exists to record.

---

## Tier 1 — Portable methodology (the default version)

| Area | Files | Portable because |
|---|---|---|
| **Router + engagement model** | `SKILL.md` | Routes on your situation, not on a target. Reads whatever `auth.json` you give it. |
| **Vulnerability classes** | ~70 class docs (`idor-access-control.md`, `ssrf.md`, `jwt.md`, `sqli.md`, `graphql.md`, `websocket.md`, `framework-misconfig.md`, `deserialization.md`, `request-smuggling.md`, …) | Technique, payloads, and the measurement that proves it. No target assumptions. |
| **Engagement phases** | `recon.md`, `web-hunt.md`, `initial-access.md`, `pivoting.md`, `privesc-windows.md`, `privesc-linux.md`, `active-directory.md`, `lateral-movement.md`, `persistence.md` (where present), `cloud.md`, `cloud-aws.md` | Phase flow is independent of who is running it. |
| **Judgement and discipline** | `validate.md`, `controls-and-oracles.md`, `engagement-ceiling.md`, `work-claims.md`, `parameter-deep-dive.md`, `reporting.md` | The highest-value docs in the repo and the most portable. This is the reasoning layer. |
| **Agents** | `agents/*.md` (6) | Pin a Claude model tier and a tool grant; otherwise generic. Change the `model:` line if you prefer a different tier. |
| **Automation** | `scripts/*.py`, `scripts/*.sh` (24) | Stdlib-only Python and POSIX bash. Scope comes from `MORAA_SCOPE_TLDS` or an argument, never from a hardcoded domain. |
| **Detection content** | `templates/*.yaml` (7), `scripts/data/*.json` | Standard nuclei templates and fingerprint data. |
| **Tests + self-check** | `tests/` (305 tests), `scripts/check_docs.py` | Prove a clone is intact before you trust it. |
| **Engagement scaffold** | `engagements/_TEMPLATE/`, `auth.example.json` | The shape of per-target state. Fill, do not edit. |

---

## Tier 2 — Operator layer (my setup, not the default)

Published because a working reference beats an abstract instruction. **Read these as "here is one
answer", then write your own.**

| File | What it encodes | Yours will differ if |
|---|---|---|
| `loadout.md` | Toolbox: WSL2 + Kali baseline, install commands per tool, wordlist paths, and a smoke test that proves the kit works *before* an engagement needs it | You are on native Linux or macOS, use a different distro, or keep wordlists elsewhere. **The smoke-test habit is the transferable part; the paths are not.** |
| `burp-mcp.md` | Driving Burp Suite from the agent via the PortSwigger MCP Server BApp, plus `scripts/burp_bridge.py` for shell-only agents with no MCP client | You do not use Burp, run it on another host, or use a different proxy. Paths show `C:\Users\<you>\...` — substitute yours. |
| `glm-delegation.md` | Why a Claude subagent cannot run on a third-party model, and the shell-out pattern that works around it | You run a single engine, or a model router / proxy. |
| `fleet-discipline.md` | Rules for orchestrating delegated implementers: sequential by default, verify the tree, disjoint file sets, never trust a progress report you did not verify | You do not delegate. **Rule 1 (concurrency kills, verify before you believe) generalises to any multi-agent setup.** |
| `delegation-hunt-brief.md` | Fill-in brief for handing a hunt to a shell-only agent | You do not delegate hunting. |
| `cheatsheet.md` | Speed reference once the kit is up | Your muscle memory is different. |
| `engage.ps1` | PowerShell scaffolder for `engagements/<target>/` from `_TEMPLATE` | You are not on Windows. Mirror it in bash in ~10 lines. |
| `scripts/notion_export.py` | Builds a fixed Notion page tree from an engagement folder | You report into Obsidian, Markdown, Jira, or nothing. Delete it freely; nothing imports it. |
| `nuclei-templates.md` | Conventions for writing templates, including the `moraa-` id prefix | Change the prefix to your own handle. |
| `CUSTOM-WORKFLOW.md` | Historical design decision: one engine, what was merged from where | Kept as provenance and attribution, not as instruction. |
| `AGENTS.md` | Orientation for an agent editing this repo, including the agent-mirror rule (`~/.claude/agents/` is canonical; `agents/` holds mirrors) | Only matters if you keep the same two-location layout. |

### The one standing rule baked into Tier 2

Several Tier 2 docs assume **all tooling runs in WSL / Linux bash**, with the agent driving from
Windows. That is an operator choice, not a methodology requirement. If you run natively on Linux,
drop the WSL framing in `loadout.md` and ignore the Windows-path notes in `burp-mcp.md`; nothing in
Tier 1 cares.

---

## Tier 3 — Deliberately not published

| Not here | Why |
|---|---|
| **Live engagement folders** | Every `engagements/<target>/` except `_TEMPLATE/` holds real scope, hosts, coverage state and findings for named programs. Gitignored; never published. |
| **`auth.json`, cookies, tokens, loot** | Live credentials. Gitignored at several patterns — see `.gitignore`. |
| **Real client findings** | Confirmed and unreported vulnerabilities on named hosts. Publishing them would breach bug-bounty disclosure terms and endanger real users. The *technique* from each is here; the target is not. |
| **Real host and product names** | Replaced with the fictional placeholders documented in the README. |
| **My global `CLAUDE.md`** | Personal operating profile: how I like to be talked to, current scope authorizations, model preferences. Pure Tier 2, and useless to anyone else. |
| **Internal changelogs and audits** | `docs/` build plans, workflow-review changelogs, merge plans — they name private repos, local paths, and delegation lanes. No value outside the original setup. |
| **Stale `.bak-*` backups** | ~74 dated backup files carrying pre-sanitization text. Git history is the backup. |
| **Target-specific one-off scripts** | Per-engagement scratch scripts written for a single program. Not methodology. |

---

## Making it yours in 15 minutes

```bash
# 1. Scope the tooling to your target instead of a hardcoded domain
export MORAA_SCOPE_TLDS="target.com,target-cdn.net"

# 2. Verify your toolbox honestly, then install what is missing (loadout.md has the commands)
bash scripts/doctor.sh

# 3. Prove the clone is intact before you trust it
python3 scripts/check_docs.py && python3 -m unittest discover -s tests

# 4. Scaffold your first engagement
cp -r engagements/_TEMPLATE engagements/<target>
cp auth.example.json engagements/<target>/auth.json   # then fill it; it is gitignored
```

Then, optionally:

| Want | Do |
|---|---|
| A different model tier per agent | Edit the `model:` line in `agents/*.md`. |
| No Burp | Ignore `burp-mcp.md`; the class docs all give a `curl` path. |
| A different report target | Replace `scripts/notion_export.py`; read `reporting.md` for the finding schema it consumes. |
| No delegation | Delete `glm-delegation.md`, `fleet-discipline.md`, `delegation-hunt-brief.md`. Run `check_docs.py` afterwards and clear any now-dangling router rows it reports. |
| Your own nuclei namespace | Change the `moraa-` id prefix in `templates/*.yaml` and `nuclei-templates.md`. |
| Native Linux instead of WSL | Drop the WSL sections of `loadout.md`; reimplement `engage.ps1` in bash. |

A note on removals: `check_docs.py` is the safety net. Delete whatever you like, then run it — it
will name every dangling router row and unresolved wiki-link so a trimmed library stays coherent.
