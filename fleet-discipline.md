# Moraa — Fleet discipline (delegation that doesn't lie to you)

> **Tier 2 — operator layer.** This doc describes *one* working setup, published as a
> reference rather than a requirement. Yours will differ; nothing in the methodology
> depends on it. See [CUSTOMIZATION.md](CUSTOMIZATION.md).

> Written 2026-10-01 after delegation failed repeatedly on 2026-09-29/30 — four separate failure
> modes in two days, none of them documented anywhere in the library. These are operational rules,
> not suggestions: each one was learned by an orchestration run that reported progress that never
> happened. Cross-ref [[glm-delegation]] (the model-tier/lane question this doc assumes is settled).

## Rule 1 — Concurrency kills. Run delegations SEQUENTIALLY unless you have measured headroom

- Four Opus subagents dispatched at once hit the Anthropic session limit — the runs didn't queue,
  they failed.
- Three parallel z.ai relay calls hit a 429 rate limit; the client retried 20 times and **all 20
  retries failed**. Retrying into a rate limit doesn't clear it, it proves you're still rate-limited.

```text
# the pattern that works: one implementer at a time, gate on its VERIFIED output
dispatch task-1  →  verify tree  →  dispatch task-2  →  verify tree  →  ...
# parallelism is earned: after you have measured that N concurrent runs complete cleanly,
# N is your headroom. Until measured, N = 1.
```

## Rule 2 — The 600s stall watchdog kills agents that WAIT; dispatch the external CLI directly

A Claude agent that hands off to a long-running external call and then idles gets killed by the
stall watchdog at 600s. The agent isn't stuck because the work is hard — it's stuck because its
only job is *waiting*, and waiting is indistinguishable from dead.

**If the real work is in an external CLI, run that CLI directly from the orchestrator (Bash with
a timeout / background + poll). Don't wrap it in an agent whose whole body is "run X and wait".**

```bash
# direct dispatch — the orchestrator owns the timeout, nothing idles
timeout 1800 pi -p --provider zai --model glm-5.3-flash --thinking max "<task>" > /tmp/delegate1.log 2>&1 &
# then poll the working tree (Rule 3), not the process's feelings
```

## Rule 3 — The interface matters: verify the tree, never the self-report

A one-shot print flag (`-p` and friends) may not engage a coding CLI's tool loop **at all**: the
process runs, returns text, writes NOTHING, and exits 0. A delegation that "completed" without
touching the working tree did not complete — it chatted.

```bash
# BEFORE dispatch: snapshot the tree
find . -newer /tmp/dispatch-marker -type f 2>/dev/null | head    # or: git status --porcelain
touch /tmp/dispatch-marker
# AFTER the CLI returns: judge by files, not by its final message
find . -newer /tmp/dispatch-marker -type f -not -path './.git/*'
# empty output = the delegation produced nothing, whatever it claimed
```

**Check the working tree, not the agent's self-report.** Same discipline as the REVIEW GATE in
[[glm-delegation]], applied to existence rather than quality.

## Rule 4 — Partial work survives a dead agent — inspect before re-dispatching

A watchdog-killed or crashed run is not a clean rollback: it often left real, usable output in
the tree (half-implemented modules, a finished one of three tasks, notes). Re-dispatching from
scratch over that wastes the surviving work and can duplicate/conflict with it.

```bash
# after ANY dead run, before re-dispatch:
git status --porcelain                 # what changed?
git diff --stat                        # how much survived?
ls -la <event-log-or-log-dir> 2>/dev/null   # how far did it get?
```

Fold the survivors into the task plan, then dispatch only the remainder.

## Rule 5 — Concurrent writers get DISJOINT file sets; shared router files are single-writer

When parallelism *is* justified (measured headroom, Rule 1), never let two writers touch the same
file — and **forbid all of them from shared router/wiring files** (in this library: `SKILL.md`,
`web-hunt.md`, index tables). Two agents editing the router at once interleave half-wired rows.

```text
per-agent brief:
  "You may create/modify ONLY: <disjoint module file set>. NEVER edit SKILL.md, web-hunt.md,
   or any shared index. Instead write the wiring you need (one router row, one class-table row)
   to <module>/WIRING.md. The orchestrator applies all WIRING.md notes in ONE pass afterwards."
```

Then the orchestrator applies the collected wiring once, in a single edit — one writer, one
consistent router.

## The 60-second pre-flight (run before every delegation batch)

1. How many concurrent runs? Default **1**; justify any N > 1 with measured headroom.
2. Long external call involved? Dispatch the CLI directly, not an agent that waits.
3. What FILE evidence will prove this run worked? Check for it before believing any report.
4. Was a previous attempt here? Inspect the tree/log for surviving partial work first.
5. Do any two runs share a file? If yes, serialize them or carve disjoint sets + WIRING.md.

## Rule 6 — Parallel HUNTS claim hosts; a queue is not a lease

Two parallel GLM shards once each read the same ten-target HUNT-QUEUE, each concluded it owned all
of it, and the job ran twice. Rule 5 keeps file *edits* from colliding; it does not stop two
hunters from *hunting the same host*. Hunt-target coordination is [[work-claims]]: the orchestrator
assigns disjoint shard lists at dispatch, each run creates `.claims/<host>.md` before its first
packet, `coverage.md` stays append-only while any claim is ACTIVE, and one merge pass over
`runs/` rebuilds HUNT-QUEUE.md when the last claim closes. Rule 5 = don't edit the same file;
Rule 6 = don't hunt the same host.

---

## Dispatch mechanics that silently eat work (all three hit in one session)

**1. A long heredoc gets truncated, and the failure looks like a quoting bug.** Writing a 140-line
brief with `cat > brief.txt <<'EOF' … EOF` failed three times with
`unexpected EOF while looking for matching '` — which reads like a stray apostrophe in the content
and is not. The command was truncated before its terminator, so the shell parsed the rest of the
brief as commands, and the first `'` in ordinary prose ("the admin's token") blew up. **Write long
briefs in 30-60 line chunks** (`>` for the first, `>>` for the rest) and `wc -l` after each to
confirm it landed. The same applies to any long generated doc.

**2. In auto mode the dispatch itself can be refused.** Launching an unsandboxed implementer CLI can
trip the harness classifier (`Create Unsafe Agents`) even when `Bash` is blanket-allowed in
settings — the classifier judges what the command *does*, not tool permission, so adding another
allow-rule does nothing. `--read-only` is not a substitute: it strips `bash`/`write`, so the lane
cannot produce its deliverable. Either leave auto mode for the dispatch or hand the operator the
exact command. **Do not try to route around the refusal.**

**3. Lane output can be correct data in a broken shape — review the file, not the row count.** A lane
briefed to append `VERDICT\tCODE\tMSG\tBYTES\tPATH` wrote the probe tool's raw multi-tab output into
a 6-column schema, so every row spilled and wrapped. The data was all there and all correct; a
`wc -l` progress check looked perfect. **Open the file and eyeball ten rows before you trust any
lane's output**, and prefer briefing a lane to append *one preformatted field per column* rather
than piping a tool's raw stdout into a schema.

### What GLM lanes are actually good for on this evidence
Across one engagement: four analysis/hunting lanes produced nothing but file headers before being
timeout-killed; the lanes that worked were **bulk mechanical** — downloading bundles, and sweeping a
fixed route list with a fixed tool while appending a row per request. Shape the brief to that:
a concrete input list, one tool invocation per item, one appended row per result, and an explicit
"write every row as you go, a partial file is a success" instruction. Reserve judgment calls —
is this a bug, what is the severity, what do we test next — for the orchestrator.
