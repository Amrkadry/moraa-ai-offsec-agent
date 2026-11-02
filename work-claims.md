# Moraa — Work claims: parallel hunts that don't collide

> Written 2026-10-02 after a real failure the same day: two parallel GLM shards each read the same
> 10-target HUNT-QUEUE, each concluded it owned all of it, and the job ran twice; in the same
> session three writers nearly interleaved `coverage.md`. [[fleet-discipline]] Rule 5 keeps file
> *edits* from colliding; it does nothing about two hunters *hunting the same host*. This doc is
> the hunt-side convention: a claim/lease file per unit of work, disjoint shard lists at dispatch,
> append-only coverage while runs are live, and one merge pass at the end. The idea a swarm
> runtime solves with per-agent cursors (exactly-once delivery) — encoded as files, because our
> agents share a filesystem and no process.

## The claim file

One file per claimed unit of work, at `engagements/<target>/.claims/<scope>.md`. `<scope>` is the
host (default), `class:<class>@<host>` for one class on a shared host, or a task slug
(`sweep-js-secrets`) for non-host work.

```markdown
# CLAIM <scope>
CLAIMED-BY: <agent or relay id — bughunter | glm-shard-2 | recon>
CLAIMED-AT: <UTC timestamp, e.g. 2026-10-02T15:04Z>
LEASE-MIN: 45
STATUS: ACTIVE
RESULT: <one line, written when DONE — omit until then>
```

Rules:

1. **Claim before the first packet.** Create the file, then start work. An unclaimed host in an
   active parallel run is unassigned, not free-for-all.
2. **An existing claim answers the question.** `STATUS: ACTIVE` and `now < CLAIMED-AT + LEASE-MIN`
   → the host is another run's. Do not wait, do not "help" — pick the next HUNT-QUEUE entry.
3. **Expired lease = dead run.** `CLAIMED-AT + LEASE-MIN < now` means the claiming run died before
   releasing (watchdog kill, crashed relay). Re-claim: rewrite `CLAIMED-BY`/`CLAIMED-AT`, add
   `RECLAIMED-FROM: <previous id>` — the surviving partial work is folded in per fleet-discipline
   Rule 4, not redone.
4. **Finish → close the claim the same minute.** `STATUS: DONE` + `RESULT:` one-liner (e.g.
   `RESULT: confirmed IDOR, findings/idor-orders-invoice.md`). Verdicts still live in `findings/` —
   a claim is a *lease, not a truth record*; `.claims/` is disposable and never read by
   `context_pack.py`.
5. **Renew long work.** Bump `CLAIMED-AT` (heartbeat) before the lease lapses — a rewrite is
   cheaper than losing the host to a re-claim mid-hunt.
6. **Never delete another run's claim.** Yielding early → `STATUS: RELEASED` with a one-line
   reason. `DONE`/`RELEASED` claims can be pruned when the engagement closes.

## Sharding a queue — assign at dispatch, don't hope

Before dispatching N parallel hunt runs on one engagement, the orchestrator partitions HUNT-QUEUE
into **N disjoint host lists** and puts the list in each brief:

```
Shard: 2/3 — hosts assigned to THIS run: stg.acme.example, api.acme.example, art.acme.example
```

- A shard with no explicit list defaults to "the whole queue" — that is exactly the duplication
  failure this doc exists for. No list = don't dispatch the second shard.
- Shards still claim per host (rule 1): claims catch the residual cases — a shard finishing early
  and self-assigning more work, or an operator adding a host mid-run.
- Solo session (one hunter, no relays)? Write no claims — this convention is coordination
  overhead, and sequential-by-default (fleet-discipline Rule 1) is still the standing answer.

## coverage.md during a parallel run — append-only

`coverage.md` is the one shared file every hunt run wants to write. While ANY claim on the
engagement is `ACTIVE`:

- **Append only.** New blocks go on the end (one `cat >>`/single write per update). Never
  Edit-tool a mid-file line, never re-sort, never "tidy" — a read-modify-write against a file
  another run is appending to is how coverage gets silently lost.
- **Per-run detail goes in the per-host `TRACKER.md`** — those are naturally disjoint (one host,
  one claim, one writer).
- **The last claim closed (or the orchestrator) consolidates.** When `STATUS: DONE` on the final
  claim, that run owns coverage.md exclusively: merge tracker details, dedupe rows, re-rank. One
  writer, one pass — the same single-writer rule as fleet-discipline Rule 5, applied to the queue.

## The merge pass — turning N runs into one ranked queue

Every run writes its closing output block verbatim to `engagements/<target>/runs/<UTC-ts>-<agent>.md`
(the block is already the contract — bughunter's HOST/CONFIRMED/LEADS block, pentest's coverage
block). When the last claim closes:

```bash
ls engagements/<target>/runs/                    # what ran
python3 ~/.claude/skills/moraa-ai-offsec-agent/scripts/context_pack.py "engagements/<target>"
```

One merge pass (single writer): read every `runs/*.md` + the context pack, dedupe by
(host, class) — two runs reporting the same lead keep the one with the control fired — rank by
crown-jewel value × ease of entry, and rewrite `HUNT-QUEUE.md` **once**. `runs/` then archives;
`findings/` remains the only source of truth for what was proven.

## Why not fancier

No locks, no daemon, no pheromone decay: our agents are markdown prompts sharing a filesystem, and
parallelism here is 2-4 runs, not 40. A file whose mtime + STATUS answers "who owns this, is it
still alive" is the whole mechanism — anything more is a scheduler we'd have to keep alive.
