# Moraa — Engagement ceiling (telling "not hard enough" from "structurally blocked")

> Written 2026-10-01 from a real case (2026-09-30): five clean SSRF sweeps on one estate, and the
> question that mattered was whether a sixth sweep had any chance of being different. It didn't —
> and being able to SAY that, with evidence, was worth more than the sweep. This doc teaches the
> distinction, how to state a ceiling, and when to stop scanning and escalate.

## The distinction

- **"I have not looked hard enough"** = the class is reachable in principle, your angle or access
  was the limitation. The fix is another pass, a better angle, or a new primitive. Not a ceiling.
- **"This is structurally blocked"** = you can name WHY the class cannot fire on this estate —
  each candidate sink is individually closed for a stated reason, not just unfound. A structural
  conclusion is a deliverable. It caps a whole class and tells the operator where a primitive
  would change the answer.

The failure mode this doc exists for: treating (2) as (1) and burning pass after pass on a class
that cannot fire — or worse, claiming (2) when it's really (1).

## The real case — six SSRF passes, and the sixth was the one that closed it

An estate had five clean SSRF sweeps. The sixth pass took a genuinely new angle: instead of
re-fuzzing parameters, it **mined the host inventory for hosts whose NAME states a fetching
function** — `webhook`, `proxy`, `image`, `render`, `relay`, `preview`, `upload` — the
purpose-built fetchers, where SSRF lives if it lives anywhere.

```bash
# the angle: name-stated function mining over the host inventory (recon/known_hosts output)
for kw in webhook proxy image render relay preview upload fetch url; do
  grep -iE "(^|[-.])$kw([-.]|$)" recon/known_hosts_target.txt
done | sort -u
# then fingerprint each hit's fetch surface: what URL params does it take, and where do they go?
```

Result: **nothing — and that nothing was conclusive**, because every purpose-built fetcher fell
into a named, checked category:

- **edge-blocked to health-only** — the fetcher's URL parameter is reachable only by the load
  balancer's health check path; user-supplied URLs are rejected at the edge, verified by request;
- **a presigned-upload sink that never dereferences a user URL** — the "upload" host accepts
  bytes to a presigned target; the client hands it a *destination*, and the service never fetches
  from a URL you control — verified by reading its request contract, not by assuming;
- **signature-gated API Gateway** — every fetch-shaped route requires a request signature
  ([[request-signing]] territory), so no parameter is attacker-reachable as-is;
- **already closed** — the one genuinely interesting fetcher had been locked down; a canary
  callback test confirmed it no longer fires.

After six passes, each with a *different* mechanism, each candidate sink individually named and
closed — that is a STRUCTURAL conclusion: **the estate has no attacker-reachable URL-fetch
primitive.** Another sweep would not change that; a source-code review or an internal foothold
would. That is what a ceiling sounds like.

## How to state a ceiling (the three sentences that must be in coverage.md / the report)

1. **Name the missing primitive.** "No attacker-reachable server-side URL-fetch primitive exists
   on this estate" — one sentence, about the mechanism, not your effort.
2. **Name what would unblock it.** "Source review of the render service, or an internal network
   position, would reopen this class" — the operator learns exactly what changes the answer.
3. **Say which findings are capped by it.** "Blind-XSS, webhook-based SSRF→metadata, and any
   OOB-dependent chain are capped at not-provable here" — downstream hunters stop re-trying.

```markdown
## Ceiling — SSRF (2026-09-30, after 6 passes)
- Missing primitive: no attacker-reachable URL-fetch (all purpose-built fetchers closed: see
  findings/notes — health-only edge, presigned-upload sink, sig-gated API-GW, locked down).
- Would unblock: source review of <service>, or internal foothold (then re-run [[ssrf]] §3-4).
- Caps: OOB-only chains and SSRF→cloud-metadata paths are not reachable on this estate.
```

## When to stop scanning and escalate to the operator

Stop and hand back when **all three** hold:

- the class has been attacked from at least two genuinely different mechanisms (not the same
  payload list twice), each with its control fired ([[controls-and-oracles]]);
- every named candidate sink has an individual, stated reason it cannot fire — verified by a
  request, a contract read, or a canary, never by absence of a hit;
- the remaining unblock (source, internal access, a test tenant) is something the operator can
  grant and you cannot self-provision.

Then the honest output is a BLOCKED/ceiling entry — in the bughunter output format, the `BLOCKED:`
line is exactly for this — not another sweep.

## The inverse warning — a ceiling claimed without a class-by-class negative is just giving up

A ceiling is the *most* evidenced claim in an engagement, not a tired exit. Before writing one:

- Did you test each vuln class the primitive would feed (SSRF→metadata, webhook fetch, PDF
  render, import-by-url, avatar fetch…), or only the one you got bored of?
- Does every "closed" have evidence attached — the actual 403/health-only behavior, the request
  contract showing no URL dereference, the canary that didn't fire — per [[controls-and-oracles]]?
- Would a fresh angle (name mining, JS-bundle fetch sinks, error-message inventory, mobile API
  variants) still surprise you? Then you don't have a ceiling; you have a to-do.

One un-attempted angle is enough to void the claim. "Structurally blocked" means you can show
your work class by class; otherwise say honestly: **not exhausted, deprioritized** — and move on
to a class that pays.
