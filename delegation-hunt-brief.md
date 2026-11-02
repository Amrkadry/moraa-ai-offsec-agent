# Moraa — Delegation hunt brief (fill-in template for a shell-only agent)

> **Tier 2 — operator layer.** This doc describes *one* working setup, published as a
> reference rather than a requirement. Yours will differ; nothing in the methodology
> depends on it. See [CUSTOMIZATION.md](CUSTOMIZATION.md).

> Hand this to a delegated coding agent that has **only a shell** — pi/GLM, aider, codex (no MCP
> client, no `mcp__burp__*` tools). Fill every `<placeholder>`, delete nothing, dispatch.
> Burp access for such an agent is `scripts/burp_bridge.py` — see [[burp-mcp]] § "Driving Burp
> from a shell-only agent". Fleet-level dispatch rules (sequential by default, verify the tree,
> disjoint file sets): [[fleet-discipline]].
>
> This template encodes what previous delegation runs got wrong: hours re-deriving pre-flight
> state the operator already held, an IDOR "confirmed" against a dead second account, false
> negatives from dead tooling, and verdicts left in chat that evaporated before the next run.

Copy everything below the line into the task, with placeholders filled.

---

# HUNT BRIEF — `<target>` / `<host>`

## 1. Target and scope

- Primary host: `<host>`
- Shard: `<k/N>` — the exact hosts assigned to THIS run: `<host list>` (omit ONLY when you are the
  sole run on this engagement — an unsharded second run over an occupied queue is a duplicate, not
  backup: [[work-claims]])
- In-scope patterns: `<e.g. *.target.com, api.target.com>` (source: `<program policy / auth.json>`)
- Out of scope — do not touch: `<...>`
- Scope confirmation before your first request: **state that the hosts you will touch are covered
  by the patterns above. If you cannot confirm a host is in scope, do not send it a single packet.**

## 2. Engagement paths

- Engagement folder: `engagements/<target>/` — **your working directory IS that folder.** All
  relative paths below resolve against it.
- Credentials live in `auth.json` (never echo its contents into chat or findings).
- **Claims: before your first packet to a host, create `.claims/<host>.md`** ([[work-claims]]).
  An ACTIVE, unexpired claim = the host is another run's — skip it and say so under `BLOCKED:`.
  Close yours `DONE` + `RESULT:` the moment you finish; `coverage.md` is APPEND-ONLY while any
  claim is ACTIVE.
- Durable outputs go under `findings/`, `coverage.md`, `<host>/TRACKER.md`, `HUNT-QUEUE.md` (§10).

## 3. Pre-flight the operator has ALREADY done — do not redo it

- Prior state pack (`scripts/context_pack.py`): `<paste the pack or its path>`
- WAF canary status: `<canary endpoint → last observed status/size, when checked>`
- Session liveness: `<which sessions were verified live, when>`

Do NOT re-derive these. If you believe one has gone stale mid-run, say so in the `BLOCKED:` line —
do not silently re-run it. *(Rationale: two runs burned hours re-deriving state the operator
already had in hand.)*

## 4. Auth state

| Identity | Role | State | Verified | Expires |
|---|---|---|---|---|
| `<account A>` | attacker | `<live>` | `<how/when>` | `<ts or n/a>` |
| `<account B>` | victim | `<live \| DEAD>` | `<how/when>` | `<ts or n/a>` |

- **Hard rule: if the second account is DEAD, two-account IDOR is marked `BLOCKED`.** Never fake it
  with a fabricated id, a guessed second session, or an unauthenticated `200` re-labelled as
  cross-account access. A fabricated cross-account proof is worse than no proof.

## 5. Environment

- Work in **WSL bash**. `D:\...` = `/mnt/d/...`, and `/mnt` is **invisible to Git Bash** — if your
  tooling is Git Bash, the mount does not exist. `python3`, never `python`.
- **Burp is reachable via the bridge, NOT via MCP** — you have no MCP client:
  ```bash
  python3 scripts/burp_bridge.py ping      # PRE-FLIGHT — exit 3 = Burp down: STOP and say so
  python3 scripts/burp_bridge.py call send_http1_request '<json>'   # replay off the authed session
  ```
  Full subcommand list, exit codes, and the Collaborator / proxy-history traps: [[burp-mcp]].
  `ping` first, every session — negatives produced with Burp down are worthless, not clean.

## 6. Estate traps

Target-specific:

- `<trap: host/behaviour + what it does to naive tooling>`

Generic — every brief has needed these:

- **Wildcard-shadowed hosts** serve an identical default-app shell. Confirm what a host **SERVES**
  — response size and `<title>` — before investing any time in it.
- **Do not run nuclei** against `<hosts/paths>` — it bans egress and the ban poisons everything
  after it.
- **Wildcard DNS means resolution proves nothing.** An invented hostname resolves and serves the
  same redirect as a real one.
- **Verify your inputs are non-empty before trusting a negative.** A sweep once ran against a path
  that did not exist and reported a false clean.

## 7. Controls required before any negative is trusted

Per [[controls-and-oracles]] — fire the control BEFORE trusting the signal:

- **Two canaries** on any sweep: one known-good AND one known-bad, before / mid / after. A canary
  proves the target is answering; it does not prove your own requests are well-formed — hence two.
- **Per-distribution decode control** on any ALB/edge 403-vs-404 oracle.
- **OOB oracle self-test**: mint the Collaborator payload THROUGH THE BRIDGE, fire a control you
  know must land, confirm the control appears in `get_collaborator_interactions`, and check
  `clientIp` is not your own egress — before trusting any "no interactions".
- An empty `CONTROLS:` line in your closing block makes every negative in your report worthless.

## 8. What pays on this target

- `<crown-jewel surface + the class most likely to pay on THIS target>`
- Generic SSRF parameter sweeps are usually exhausted on this estate. Only a genuinely NEW
  fetch-shaped input justifies starting another one.

## 9. Output contract — close the run with EXACTLY this block

```
HOST:            <host>
INTAKE:          steps 1-6 complete | incomplete (<which, why>)
SURFACE:         <n> endpoints, <n> params, auth boundaries: <...>
SOURCES:         js=<done|N/A> github=<> wayback=<> nuclei=<> burp=<bridge calls or down>
CLASSES RUN:     <class list>
CLASSES SKIPPED: <class list + one-line reason each>
CONFIRMED:       <findings/<slug>.md paths, or NONE>
LEADS:           <one line each, or NONE>
CLEAN NEGATIVE:  <class/route + the evidence that makes it trustworthy>
CONTROLS:        <oracle → control fired → result — one per oracle you reported; or NONE>
CEILING:         <none | the three-sentence ceiling statement per engagement-ceiling.md:
                  missing primitive / what would unblock / which findings it caps>
BLOCKED:         <what you need and cannot self-provision, or NONE>
WROTE:           <TRACKER.md / coverage.md / HUNT-QUEUE.md paths touched>
```

`CLASSES SKIPPED` with a reason per line **is the coverage audit** — a class neither run nor
explicitly skipped is a blind spot, not a neutral. An empty `CONTROLS:` line makes every negative
in the report worthless. Emit the block even on a run that found nothing: a graded clean negative
is the deliverable in that case. Gate discipline for anything you would confirm: [[validate]].

## 10. Durable outputs — every verdict leaves a file

- Confirmed finding → `findings/<slug>.md`
- Killed at the validation gate → `findings/KILL-<slug>.md`
- Clean negative (control verified) → `findings/CLEAN-<slug>.md`
- Unproven lead → `findings/LEAD-<slug>.md`
- Plus, every run: the per-host `<host>/TRACKER.md`, the INTAKE block appended to `coverage.md`,
  and the `HUNT-QUEUE.md` entry.

Reason: `scripts/context_pack.py` builds its do-not-re-propose list from `findings/` **only**.
A verdict that stays in chat evaporates, and the next run re-burns the hours.

## 11. Rules of engagement

- **Impact first.** "Can an attacker do this right now for real harm?" If no, drop it — a marginal
  finding inflated into a critical is worse than an honest `LEAD`.
- **Prove with a real request and response** — evidence, not a status code alone.
- **A well-evidenced clean negative is a good outcome.** Do not manufacture signal to have
  "found something".
- **No state-changing writes against third-party data** (other tenants' records, shared queues,
  real users' settings). Your own accounts only.
- **Do not commit, do not push.** Leave all changes in the working tree.
