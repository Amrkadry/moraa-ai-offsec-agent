# Moraa — Validate (the gate before anything enters findings/)

> Merged from bug-bounty's 7-Question Gate + pentest evidence discipline.
> Run this BEFORE writing a finding file or report entry. Any NO → fix or drop.

---

## The 7-Question Gate (all must be YES)

1. **Can I exploit it RIGHT NOW with a real PoC?** Write the exact request/command. No working
   PoC → kill it.
2. **Does it affect a real user/asset who took NO unusual action?** No 5-precondition chains.
3. **Is the impact concrete?** money / PII / account takeover / RCE / domain compromise.
   "Technically possible" is not impact.
4. **Is it in scope, AND does it avoid needing privileged access an attacker can't get?**
   Check `auth.json` scope + `docs/` policy. "Admin can do X" is centralization risk on 99% of
   programs → kill it. "Non-admin can do X that only admin should" → valid.
5. **Is it a duplicate / already known?** (bug bounty: check Hacktivity/changelog. pentest:
   not a re-report of the same root cause.)
6. **Is it NOT on the always-rejected list?** (below) — unless chained to real impact.
7. **Would a tired triager / client reviewer agree it's real?** Read it as them.

### Q8 — Identity check (IDOR / auth-bypass / priv-esc findings only)

The single most common reason a "confirmed" access-control finding comes back N/A: it only
reproduces under one identity, which is a scoped permission boundary, not a bug. Before writing
the finding, answer all four:

```
1. Which identity found it:   [low-priv user A / high-priv user B / anon / API key]
2. Anonymous repro:           does the SAME request work with NO auth header/cookie at all?
3. Cross-identity repro:      does session A's request work reading session B's DATA (not just
                               a 200 — actual foreign-account content in the response)?
4. Stale-cred repro:          does a logged-out / expired session still return data?
```

- **IDOR/BOLA**: must reproduce as *A's session reading B's data*. If it only works with **no**
  auth at all, that's "missing auth", a different (often higher) bug — relabel it.
- **Priv-esc**: must reproduce as *low-priv session reaching high-priv data/action*. If both
  identities already see it, there's no bug.
- **Auth bypass**: must reproduce *without* a valid session. If it stops working logged out,
  it's a permissions issue, not a bypass.
- Blank answer on any of the four → treat the finding as unproven, don't write it yet.

## Evidence requirements (pentest + web)

- Exact request **and** response excerpt that proves it (not just `200 OK`).
- Copy-paste reproduction (curl / command).
- For access-control/IDOR: show **two identities** — account A's data fetched with account B's
  session.
- For internal/AD: the command, its output, and the privilege level before/after (timestamped).
- Redact secrets in the finding; keep raw creds only in local `loot/`.

## Always-rejected (web) unless chained to impact

Missing security headers (CSP/HSTS/X-Frame), missing SPF/DKIM/DMARC, GraphQL introspection
alone, banner/version disclosure w/o working exploit, clickjacking on non-sensitive pages,
self-XSS, open redirect alone, CSRF on non-sensitive action, SSRF DNS-ping only, host-header
injection alone, no rate limit on non-critical form, logout CSRF, missing cookie flags alone,
verbose errors w/o secret, internal IP disclosure, weak SSL ciphers.

## Conditionally valid WHEN chained

| Low finding | + chain | = valid |
|---|---|---|
| Open redirect | + OAuth code theft | ATO |
| SSRF (DNS only) | + internal access proof / metadata | High/Critical |
| Host header injection | + password reset poisoning | ATO |
| CORS wildcard | + credentialed exfil PoC | data theft |
| No rate limit | + OTP/2FA brute | ATO |
| IDOR read | + write/delete on same endpoint | High |
| Self-XSS | + login CSRF | stored XSS on victim |

## Kill signals (pass the gut-check but consistently N/A — one specific tell each)

| Finding | Kill signal — if you see this, stop and don't write it up |
|---|---|
| Reflected XSS | `Content-Security-Policy` header present and blocks the payload's context; no cookie/session access proven |
| SSRF — DNS callback only | Collaborator/interactsh got a DNS ping but no HTTP response with internal content |
| IDOR | The "victim" ID in the response is your own test account's (see Q8) |
| SQLi | DB error string only, no actual rows exfiltrated |
| CORS wildcard `*` | `Access-Control-Allow-Credentials` absent — `*` blocks `withCredentials`, nothing to exfil |
| Rate-limit missing | Endpoint is search/contact/non-auth, or sits behind Cloudflare rate-limiting already |
| Nuclei `info`/low template hit | Version/banner detection only, no working exploit run against the live service |
| Open redirect | No `redirect_uri`/OAuth param in the chain — pure redirect has no theft vector |
| XSS via `alert(document.domain)` | No `document.cookie` exfil, no real session-theft PoC |

**Kill-fast rules**: 5 minutes to fill in Q1's PoC or move on · more than 2 simultaneous
preconditions → kill · "admin can do X" → kill immediately · documented/changelogged behavior →
kill immediately · 30+ minutes stuck on Q3 (concrete impact) with nothing reproducible → kill.

## Every verdict gets a file (durable validation state)

A verdict that lives only in chat evaporates: the next session re-proposes the same dead lead and
re-burns the hours. **Every verdict therefore produces a durable file in `findings/`** — these are
what `scripts/context_pack.py` reads to build the do-not-re-propose list:

- **`findings/KILL-<slug>.md`** — every KILL (yours or the validator's). Four lines, no prose:

  ```markdown
  # KILL — <the claim that was killed, one line>
  - Killed by: Q<n> / kill signal — <which gate question failed, one line on how>
  - The one request that failed: <exact curl/request — a kill is itself reproducible evidence>
  - Re-open when: <the specific new evidence that would reopen this lead>
  ```

  A future run re-opens a KILL only on the evidence named in `Re-open when:` — it must never have
  to re-discover the kill from a stale `coverage.md` line. A false KILL is the expensive one:
  a false PASS costs a rejected submission, a false KILL costs a real finding forever.

- **`findings/CLEAN-<slug>.md`** — every clean negative, with the evidence that makes it
  trustworthy (which control was fired, what it returned):

  ```markdown
  # CLEAN — <class/route tested>
  - Tested: <what was swept, how>
  - Control: <the control that must read the opposite way ([[controls-and-oracles]])>
  - Control result: <what it returned — the negative only counts if the control behaved>
  ```

`LEAD-<slug>.md` and confirmed `findings/<slug>.md` conventions are unchanged.

## Severity quick-map

| Finding | Typical | |
|---|---|---|
| IDOR read PII | Medium (CVSS ~6.5) | web |
| IDOR write/delete | High (~7.5) | web |
| Auth bypass → admin | Critical (~9.8) | web |
| SSRF → cloud metadata → keys | Critical (~9.1) | web |
| SQLi data exfil | High (~8.6) | web |
| Local privesc → SYSTEM/root | High | internal |
| Kerberoast → crackable SPN | High (path to DA) | internal |
| Any path to Domain Admin | Critical | internal |
| ADCS ESC → DA | Critical | internal |

Passed the gate? → write `findings/<slug>.md` (template in `SKILL.md`), update `coverage.md`,
then `reporting.md` when assembling the deliverable.

---

## Case 28 — "business need" closes any finding whose only authority is your own least-privilege opinion

**Where it bit:** the enterprise-identity product. A fully proven, control-backed authorization finding —
the predefined HR Admin role, holding **zero `permission.*` privileges**, could attach a physical
access-control policy (including the default "Access All Doors") to any worker or any whole
department, with no caller-versus-target check. Confirmed end-to-end across three real principals
with a genuine owner ground-truth read. Policy create/delete/activate were correctly refused to
the same role, so the privilege model demonstrably existed.

**Submitted. Closed INFORMATIVE — reason: "business need".**

The vendor's position: HR Admin being able to assign door policies is **intended**. And that is a
legitimate call, because **the vendor defines what a role may do**. Nothing about the measurements
was wrong. The *conclusion* was an opinion about least privilege, and the vendor owns that opinion.

### The rule

> A finding of the form **"role R can do X, and X seems too powerful for R"** will be closed as
> by-design. Role capability is the vendor's design surface. Impact narrative does not override it
> — and the more impact you argue, the more it reads as advocacy rather than a defect.

The report in question had a strong business case: physical access defeats every logical control,
HR is the largest and most-phished admin population, and SOC 2 / ISO 27001 / PCI DSS all require
separation of duties over physical access. **None of it mattered**, because every line argued
*consequence* and none argued *contradiction*.

### What survives a "business need" rebuttal

Only a finding where **the product contradicts itself**. The boundary has to be one the vendor
built, not one you believe in:

| framing | survives? | why |
|---|---|---|
| "role R shouldn't be able to do X" | **no** | vendor owns role capability |
| "this privilege declares `resource_ids:[A]`, the server serves resource B" | **yes** | the product declared the scope |
| "the admin set this restriction and it had no effect" | **yes** | the customer's own configuration is ignored |
| "enforced on endpoint X, ignored on sibling endpoint Y" | **yes** | internal inconsistency, one of them is a bug |
| "the UI refuses this principal, the API serves it" | **yes** | the product enforces it in one layer only |
| "`create`/`delete` are gated, `assign` is not" | **yes** | inconsistency inside one feature |

### The pre-submission test

Before writing up any authorization finding, ask:

> **Can I point at something the vendor built that says this must not happen?**

Acceptable authorities: a `resource_ids` scope on the granted privilege · a setting an
administrator configured · a privilege string the gateway itself names in its refusal · a UI that
hides the surface · a sibling endpoint that enforces the same rule · a documented role
specification.

If the only authority is your own judgement about what *ought* to be least privilege, the finding
will close — regardless of how well you proved the behaviour.

### The corollary that makes negatives valuable

This is why **clean negatives are load-bearing rather than filler**. The endpoint that *does*
enforce is what converts "we think this is wrong" into "your own product disagrees with itself".
On the same engagement, the finding that held up was built entirely out of such contrasts: the
restriction honoured on four endpoints and ignored on six siblings, two other settings enforced
with dedicated error codes, and the write paths honouring a scope the read paths ignored. It never
asked the vendor to accept an opinion.

So when you close an area clean, you are not just avoiding a false positive — you are
manufacturing the control that makes the next real finding unarguable. Record which endpoint
enforced, with the exact refusal string.

### Practical ordering consequence

When a programme closes one finding as "business need", reorder the remaining backlog by
*framing*, not by severity. A Medium built on self-contradiction is worth more than a High built
on a least-privilege argument, because the Medium can be accepted and the High cannot.

## Re-running your own PoC: the fixture false-negative

Before you believe a negative on re-run, rule out your own harness. Measured on a
full eleven-PoC re-run, **four arms first came back "not vulnerable" for purely
environmental reasons** -- and the one finding that was genuinely broken looked
fine until it was instrumented.

| Symptom | What it usually is |
|---|---|
| `Can't find stylesheet to import` / `(no data uri)` / `ENOENT` | the **fixture was never created**. A read/import primitive with no target file fails exactly like a patched one. |
| the PoC prints a cheerful `ok` and nothing else | the proof is a **written file**, not stdout. Check the artefact's **mtime**, not the log. |
| `lifecycle_function_unavailable`, `mount(...) is not available on the server` | the package resolved to its **server** export. `node --conditions browser`. If the bug is client-only, this is the finding, not an obstacle. |
| `This package is ESM only but it was tried to load by require` | `npm init -y` wrote a CommonJS `package.json`. Add `"type": "module"`. |
| every arm fails with `Connection refused` | the service never started. A readiness loop that prints success on timeout will hand you a full sheet of false FAILs. |

**Rules that follow:**

1. **A PoC must create its own fixtures and assert they exist.** Otherwise it
   decays into a clean negative the moment the directory is cleaned.
2. **Instrument the consumer, not the filesystem.** For a path-traversal write,
   log what the sink actually *received*. One line -- `params.slug =
   "KIT_PRERENDER_ESCAPED"` instead of `"../../../../../../KIT_..."` -- settled a
   finding that three filesystem sweeps had left ambiguous.
3. **Every readiness loop asserts and aborts.** `if not ready: dump the log; exit 1`.
4. **Sandbox a traversal so the escape lands inside a directory you created.**
   Put the app N levels deep so `../` x N resolves onto the sandbox root. Never
   write fixtures into real parent directories to satisfy a depth.
5. **A negative control holding does not validate the positive arm.** In the case
   above the crawled-link control held exactly as written up, while the positive
   arm did not reproduce at all. They are independent claims.

