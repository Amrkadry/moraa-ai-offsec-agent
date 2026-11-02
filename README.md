# Moraa AI Offsec Agent

**An offensive-security methodology that an AI coding agent can actually execute.**

Moraa is a single [Claude Code](https://claude.com/claude-code) skill pack that turns an AI agent
into a disciplined offensive-security operator. It merges external **web / cloud / web3 bug-bounty
hunting** with internal **network and Active Directory penetration testing** into one flow, driven
from a per-target engagement folder and gated by an evidence-first validation discipline.

It is **not a scanner and not an exploit kit.** It ships no weaponised exploits, holds no target
data, and automates nothing that touches a host without your explicit authorization. What it ships
is *judgement*: 88 methodology documents that encode which question to ask next, which signal is a
lie, and what separates a real finding from a `200 OK`.

> ### Authorized use only
> This is methodology for **authorized** security testing — your own systems, systems you are
> contractually engaged to test, bug-bounty programs whose scope you have read, and CTF or lab
> environments. Testing systems you do not have permission to test is illegal in most
> jurisdictions. Nothing here is an invitation to do it. See [SECURITY.md](SECURITY.md).

---

## Why this exists

Most AI-agent security tooling fails in one of two ways: it dumps an entire knowledge base into
context and the agent drowns, or it runs a scanner and reports the noise as findings. Moraa is
built against both failure modes.

| Failure mode | What Moraa does instead |
|---|---|
| Agent drowns in a 100-doc knowledge base | `SKILL.md` is a **router**. It reads your situation and loads *exactly one* phase or class doc. Never the library. |
| Scanner output reported as findings | **THE ONE RULE** (below) plus a 7-question validation gate every candidate must clear before it is written down. |
| Agent re-tests closed ground every session | **Negatives persist as files.** Killed leads and clean negatives get verdict files with a kill reason and a re-open condition. |
| Agent trusts a signal that is actually a control | `controls-and-oracles.md` — before trusting any signal, fire a control that *must* produce the opposite result. |
| Agent claims impact it never proved | Evidence-first: the exact request **and** response, a copy-paste reproduction, and for access-control claims a two-account proof. |

### THE ONE RULE

> *"Can an attacker do this **right now** and cause real harm — stolen money or PII, account
> takeover, code execution, domain compromise?"*
>
> If no, stop, do not write it, move on. "Could theoretically..." is not a finding.

Every doc in this library is downstream of that question.

---

## Install (5 minutes)

```bash
git clone https://github.com/Amrkadry/moraa-ai-offsec-agent.git \
  ~/.claude/skills/moraa-ai-offsec-agent

# make the agents available in every session
mkdir -p ~/.claude/agents
cp ~/.claude/skills/moraa-ai-offsec-agent/agents/*.md ~/.claude/agents/
```

Then verify your toolbox and prove the library is structurally sound:

```bash
cd ~/.claude/skills/moraa-ai-offsec-agent
bash scripts/doctor.sh                 # checks every tool the methodology assumes; reports API-key presence, never values
python3 scripts/check_docs.py          # exit 0 = library self-check passes
python3 -m unittest discover -s tests  # 305 tests, ~15s
```

**Requirements:** Python 3.9+ (standard library only, no `pip install`), bash, and whatever
offensive tooling you choose to install — `loadout.md` lists it with install commands and a smoke
test. Everything runs on Linux, macOS, or WSL2 on Windows.

Use it by invoking the skill (`/moraa-ai-offsec-agent <target>`, or just describing an
offensive-security task) or by calling an agent directly: `@bughunter`, `@recon`, `@pentest`.

---

## What's inside

| | Count | What |
|---|---|---|
| **Methodology docs** | 88 root + 10 nested | One doc per vulnerability class or engagement phase |
| **Automation scripts** | 24 (16 Python, 8 shell) | Stdlib-only recon, detection and triage pipeline |
| **Agents** | 6 | Specialised subagent definitions |
| **Nuclei templates** | 7 | High-signal checks public template sets miss |
| **Tests** | 11 files / 305 tests | `python3 -m unittest discover -s tests` |

### The six agents

| Agent | Role |
|---|---|
| `bughunter` | **Primary hunter.** Impact-first web and cloud hunting for RCE / ATO / Critical. One class at a time, chains A to B, evidence-only claims. |
| `recon` | **Breadth.** Subdomains, DNS brute force, favicon-hash pivoting, JS bundle mining, content fuzzing. Enumerates; never exploits. |
| `pentest` | **Full coverage.** Every port, service and class; banner-grab to CVE mapping; internal AD track post-foothold. |
| `cloud-offensive` | **Cloud attack paths.** Asset and IAM graph into a path engine to crown jewels, every hop proven, blast-radius model. |
| `validator` | **Independent gate.** Returns PASS / KILL / DOWNGRADE / CHAIN-REQUIRED on a candidate. Catches self-fooled IDOR claims. |
| `chain-builder` | **Escalation.** Turns a confirmed low or medium bug A into a *proven* A-to-B-to-C chain. Never "could chain with". |

### Coverage at a glance

**Web and API** — IDOR / broken access control, SSRF (with cloud metadata for AWS, Azure, GCP,
Alibaba, Tencent, Huawei), auth / OAuth / SAML / JWT / password reset, SQLi, NoSQL-LDAP-XPath
injection, SSTI, deserialization, XSS, CSRF, CORS, XXE, LFI, file upload, command injection,
request smuggling, race conditions, prototype pollution, mass assignment, parameter pollution,
GraphQL, gRPC, WebSocket / CSWSH, open redirect, clickjacking, postMessage, HTML and CSS injection,
ReDoS, host header, cache poisoning, XS-leaks, 4xx and WAF bypass, rate-limit bypass, 2FA bypass,
business logic, multi-tenancy, shadow APIs, session management, request signing, padding oracles.

**Framework and platform** — Next.js, Nuxt, SvelteKit, Spring and NestJS misconfiguration,
source-map mining, API-gateway route detection, WordPress / Joomla / Moodle, Supabase and BaaS RLS
bypass, Okta, Microsoft 365 and Entra, VMware vCenter, enterprise VPN, Kubernetes, CI/CD, MCP
server security, supply chain, agentic-browser hijack, AI/LLM red teaming and RAG/vector attacks.

**Infrastructure and internal** — recon and attack-surface mapping, initial access, pivoting and
tunnelling (ligolo-ng first), Windows and Linux privilege escalation, Active Directory, DCSync,
lateral movement, credential access, persistence, egress-filter bypass, cloud attack paths (with an
AWS-specific track), subdomain takeover, DNS rebinding.

**Mobile, web3, discipline** — mobile (APK/IPA) pentest, web3 and smart-contract audit, meme-coin
audit, the validation gate, reporting (HackerOne / Bugcrowd / CPTS formats), engagement ceiling,
controls and oracles, parameter deep-dive.

---

## How it works

`SKILL.md` is the router. Work accumulates in a per-target engagement folder, which is where all
state lives — not in the agent's context window:

```
engagements/<target>/
  ENGAGEMENT.md    scope, rules of engagement, authorization note, crown jewels
  auth.json        scope + cookies + bearer + the two-account pair for IDOR testing
  docs/            program policy, API specs, BloodHound zips
  coverage.md      what is tested / untested / confirmed - the "what next" driver
  findings/        one <slug>.md per confirmed finding, evidence-backed
  recon/ loot/ pivot/ graph/
  report/          deliverable assembled from findings/
```

Copy `auth.example.json` to `engagements/<target>/auth.json` and fill it once; the skill reads it,
sets scope, and loads the two credentials used for two-account IDOR testing. Everything under an
engagement folder except the template is gitignored.

Candidates must clear the `validate.md` gate before anything enters `findings/`. Verdicts persist
as `findings/KILL-<slug>.md` and `CLEAN-<slug>.md`. At any point:

```bash
python3 scripts/context_pack.py engagements/<target>
```

distils the whole engagement into a 1-2 page brief — confirmed, leads, killed, clean negatives,
open blockers — so a new session resumes in seconds instead of re-deriving state. **This is the
mechanism that makes the work compound** instead of resetting every session.

### Scoping the tooling to your target

The scripts bake in no target. Point them at your scope with an environment variable:

```bash
export MORAA_SCOPE_TLDS="target.com,target-cdn.net"
```

---

## Start here

1. Read `SKILL.md`, sections "THE ONE RULE" and "0. ENGAGE" — the whole method is about ten minutes of reading.
2. Install (above), then `bash scripts/doctor.sh` to verify your toolbox.
3. Read `loadout.md`, install what you are missing, and run its smoke test.
4. Start an engagement: `/moraa-ai-offsec-agent <target>`, fill `auth.json`, keep `coverage.md` honest.
5. Hunt with `@bughunter`, or `@recon` first on an unknown surface.
6. Before writing any finding, run the `validate.md` gate or hand the candidate to `@validator`.
7. Write it up with `reporting.md`.

---

## Examples in this library are fictional

Many docs teach a technique from a real measured case, because a lesson with a measurement attached
is worth more than an abstract rule. **Every host, domain, product name, cookie name and identifier
in those examples has been replaced with a fictional placeholder** before publication:

| Placeholder | Stands for |
|---|---|
| `acme.example`, `*.svc.acme.example` | a large consumer and prosumer SaaS estate |
| `acme-legacy.example`, `acme-nms.example` | the same vendor's legacy and appliance-management domains |
| `saasvendor.example` | a multi-tenant SaaS platform |
| `target.com`, `attacker.com`, `evil.com` | generic placeholders, already used throughout |
| "the vendor", "the appliance OS", "the NMS appliance" | an unnamed network-hardware vendor and its products |

No real client, program, host, credential, token or undisclosed vulnerability appears anywhere in
this repository. The measurements, status codes, header behaviours and reasoning are real; the names
are not. Third-party domains that *do* appear — cloud-provider metadata endpoints, subdomain-takeover
fingerprints, public research citations — are public reference data.

---

## Customizing it

What is in this repo is the **general, portable version**. The operator layer — which shell, which
Burp wiring, which model runs which lane, where your wordlists live — is deliberately separate, so
you can swap it for yours without touching the methodology.

**[CUSTOMIZATION.md](CUSTOMIZATION.md)** maps exactly which files are portable methodology, which
are one operator's personal setup, and what to change to make it yours.

## Provenance

Moraa was assembled, not invented from nothing. `CUSTOM-WORKFLOW.md` records the original design
decision and what came from where: web methodology and the validation gate from
[`claude-bug-bounty`](https://github.com/shuvonsec/claude-bug-bounty); AD, lateral-movement and
exploit-dev material from an `offensive-*` skill collection; and the engagement-folder, single
`auth.json` and coverage-matrix *ideas* from PentesterFlow. Pivoting and tunnelling, both privesc
tracks, `controls-and-oracles.md`, `validate.md`'s durable-verdict model, and the connective tissue
from a web foothold to internal compromise were written from scratch. Techniques sourced from
published research are attributed in the doc that uses them.

## Related

- [dotnet-codereview-framework](https://github.com/Amrkadry/dotnet-codereview-framework) — sibling project for .NET code review.

## Contributing

A doc earns its place by carrying a **command and an outcome**, not a description. `check_docs.py`
enforces the structural half of that: balanced code fences, no command-less technique doc,
resolvable wiki-links, router targets that exist, no orphan root docs, every routed class visible in
`web-hunt.md`'s class table, and the MANUAL-ONLY invariant. Run it and the test suite before
opening a PR. Do not add client-identifying examples — genericise them the way the table above does.

## License

MIT — see [LICENSE](LICENSE). Portions adapted from open-source projects under their respective
licenses, attributed per file where directly sourced.
