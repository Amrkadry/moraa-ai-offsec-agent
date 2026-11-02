# Moraa — Controls & Oracles (fire the control BEFORE you trust the signal)

> Written 2026-10-01 after a real engagement (2026-09-29/30) produced **five separate false
> positives from one root cause**: every one trusted an oracle that had never been controlled.
> Cross-ref [[bypass-4xx]] (decode + canary controls), [[burp-mcp]] (Collaborator polling trap),
> [[recon]] §1a (the crt.sh `n`-prefix artifact), [[ssrf]] (OOB discipline),
> [[parameter-deep-dive]] §0 (baseline oracle), [[validate]] (the gate this doc feeds).

## The principle

**BEFORE you trust any signal, fire a control that MUST produce the opposite result. If the
control does not behave, your negative AND your positive are both worthless.**

A scanner result, a fuzz hit, a 403, a resolution, an empty OOB poll — none of these is evidence.
Each is an *oracle reading*, and every oracle needs a calibration: one input you know must read
"yes" and one you know must read "no". If the calibration fails, the instrument is broken, and
every reading you took with it is noise — including the ones that looked like wins.

---

## Case 1 — WAF-poisoned fuzz: every path 403s, `-fc 404` scores them ALL as hits

A large ffuf run tripped CloudFront's rate rule mid-run. From that moment every path — real or
invented — returned the edge's HTML 403. The filter was `-fc 404`, so ffuf scored all ~40
remaining paths as "discovered routes". Phantom surface, confidently reported.

**Control: a canary request before AND after the run. If the canary changed, discard the entire
result set — not just the suspicious rows.**

```bash
# 1. canary BEFORE the run — must be the app's normal response (200)
curl -s -o /dev/null -w 'canary-pre  %{http_code} %{size_download}\n' "$H/status"

# 2. fuzz slowly, filter the edge page by SIZE not just status
ffuf -u "$H/v1/organizations/$ID/FUZZ" -w words.txt -H "Cookie: $AUTH" \
     -fc 404 -fs 919 -t 5 -rate 20 -s        # 919 = CloudFront "Request blocked" body

# 3. canary AFTER — if this is not 200, THROW AWAY the whole result set and back off
curl -s -o /dev/null -w 'canary-post %{http_code} %{size_download}\n' "$H/status"
```

**Impact gate:** a route counts only if a hand request from a cold state (minutes after the run,
no burst) returns the app's response — a different body from the edge block page AND from the
app's 404. Full method: [[bypass-4xx]] § "The canary control".

## Case 2 — Stale output file: `curl -o out` does NOT write on connection failure

`curl -o body.json HOST/api/...` leaves `body.json` **untouched** when the connection fails —
and `%{http_code}` is `000`. A loop that reads the file after every curl therefore shows the
**previous host's body**. On the 2026-09-29 pass, three dead hosts appeared to return live JSON
because the file still held the last live host's response.

**Control: a fresh `mktemp` per request, and check the status code before reading any body.**

```bash
# WRONG — dead host leaves out.json holding the PREVIOUS request's body
for h in $(cat hosts.txt); do
  curl -s -m 10 -o out.json "$h/api/config"
  jq -r 'keys[]' out.json          # reads whatever was there before
done

# RIGHT — fresh file per request; never read a body without its status code
for h in $(cat hosts.txt); do
  out=$(mktemp); code=$(curl -s -m 10 -o "$out" -w '%{http_code}' "$h/api/config" || true)
  if [ "$code" = "000" ] || [ -z "$code" ]; then echo "$h DEAD (no response)"; rm -f "$out"; continue; fi
  echo "$h -> $code"; jq -r 'keys[]' "$out" 2>/dev/null; rm -f "$out"
done
```

**Impact gate:** "host X leaks config" requires the body **and** its status code captured from
the same request — re-run the single request by hand and show both before it goes anywhere.

## Case 3 — S3 `403 AccessDenied` is NOT proof a file exists

With `s3:ListBucket` denied on the bucket, S3 returns `403 AccessDenied` for a **missing**
object too — identical body for "exists but you can't list" and "doesn't exist". Reading a 403
as "the backup zip is there, locked" is fiction.

**Control: request a deliberately-absent path under the same prefix. Identical response means
your original "hit" proves nothing.**

```bash
B="https://target-bucket.s3.amazonaws.com"
# candidate "find"
curl -s "$B/backups/site-2026-06.zip" | grep -o '<Code>[^<]*</Code>'
# CONTROL — a name that cannot exist (uuid). Same answer => first response was uninformative.
curl -s "$B/$(uuidgen)-definitely-not-here.zip" | grep -o '<Code>[^<]*</Code>'
# Only `NoSuchKey` on the control + a DIFFERENT response (200/`NoSuchBucket`-style XML, redirect,
# range behavior) on the candidate says anything. Identical `AccessDenied` on both = no signal.
```

**Impact gate:** a private-bucket claim needs positive proof — a readable object with real
content, a listing, or a write. "AccessDenied therefore it exists" is not a finding; the control
exists precisely to kill this one.

## Case 4 — Out-of-band blind spot: an unpollable payload polls as "no interactions" FOREVER

Burp MCP's `get_collaborator_interactions` only returns interactions for payloads **minted by
that Burp instance's own Collaborator client**. A payload pasted in by hand — from the Burp UI,
a teammate, a previous session — polls as `No interactions detected` forever, no matter what the
target actually did. A blind SSRF that fired perfectly looks identical to one that never fired.

**Control: mint via `generate_collaborator_payload`, fire a request you KNOW must land at it,
and confirm the interaction appears — BEFORE trusting any negative. Then check `clientIp` is not
your own egress IP** (your own IP means you saw your control, not the target).

```
mcp__burp__generate_collaborator_payload   (customData: "<what you are testing>")
# control — this MUST produce an interaction:
curl -s -o /dev/null -w "%{http_code}\n" "http://control.<payload>.oastify.com/canary"
mcp__burp__get_collaborator_interactions   # control present? if NOT, every negative is worthless
```

**Impact gate:** a blind-SSRF finding needs an interaction whose `clientIp` belongs to the
target's infrastructure, plus internal content or a second-order effect (see [[ssrf]] §4 and
[[validate]]'s kill signal "DNS callback only"). Full trap write-up: [[burp-mcp]] § "The
Collaborator polling trap".

## Case 5 — Fabricated recon: grep across a JSON newline separator + wildcard DNS confirms fiction

`crt.sh` returns `name_value` as a newline-separated list inside ONE JSON string. A hostname
regex run over the raw response matches **across** that separator, inventing `n`-prefixed hosts
(`acme.example\nwww.acme.example` → `nwww.acme.example`). On 2026-09-29 a naive grep reported 478 new hosts on
acme.example; parsed correctly, the true count was **1**. Worse: on a wildcard domain every invented
name RESOLVES and serves the same redirect as a real one — so "does it resolve?" validates the
fiction perfectly.

**Control: parse as JSON; verify a host by WHAT IT SERVES (response size and `<title>` against
the target's known default-app shell), never by resolution.**

```bash
# WRONG — regex over raw JSON crosses the \n inside name_value
curl -sk "https://crt.sh/?q=%25.TARGET&output=json" | grep -oiE '[a-z0-9_*.-]+\.TARGET'

# RIGHT — parse; split name_value on newlines FIRST
curl -sk "https://crt.sh/?q=%25.TARGET&output=json" > /tmp/crt.json
python3 - <<'PY' | sort -u
import json
for row in json.load(open('/tmp/crt.json')):
    for f in ('name_value','common_name'):
        for n in (row.get(f) or '').split('\n'):
            n = n.strip().lstrip('*.').lower()
            if n.endswith('.TARGET'): print(n)
PY
# VERIFY by what it serves — NOT by resolution (wildcard DNS makes fiction resolve)
curl -sk "$CAND" -o /tmp/body -w '%{http_code} %{size_download}\n'; grep -o '<title>[^<]*' /tmp/body
# same size+title as every other host = wildcard shell, not a discovery
```

**Impact gate:** a "new host" counts only when it serves something measurably different from the
domain's wildcard catch-all. Full write-up: [[recon]] §1a "THE TRAP".

---

## Case 6 — the `000` mirage: a sweep whose requests were never sent
*(Added 2026-10-01, from `tenant-cloud.svc.acme.example`.)*

A 497-name sweep reported **574 "anomalies"** and looked like a jackpot. Every one was HTTP `000`.
The wordlist lived on `/mnt/c` with **CRLF** line endings, so every URL carried a trailing `\r` and
curl rejected it locally. Not one request left the machine.

```bash
curl .../api/ads          # -> 404   clean path, reaches the origin
curl $'.../api/ads\r'     # -> 000   same path + CR, never sent
```

**`000` is neither a finding nor a block — it is a request that was never made.** Writing those
rows up as "blocked" or "anomalous" would be fabrication from an empty result set.

**Why the canary did not save me — this is the important part.** The canary URL was a shell literal
with no `\r`, so it kept returning a healthy `404` before, during and after the run while every real
request failed. **A canary proves the TARGET is still answering; it does not prove YOUR OWN requests
are well-formed.** The two failure modes are independent and need independent guards:

| Guard | Catches |
|---|---|
| canary (known-good + known-bad, before / mid / after) | the target or edge changing under you — rate bans, WAF trips |
| connection-failure guard (abort on first `000`) | your own tooling being broken — malformed URLs, DNS, TLS, proxy down |

```bash
# both guards, minimal form
c=$(curl -s -o /tmp/r -w "%{http_code}" -m 15 "$H$p")
[ "$c" = "000" ] && { echo "CONNECTION FAILURE at '$p' — run INVALID"; exit 3; }
if [ $((n % 25)) -eq 0 ]; then
  [ "$(canary)" != "404" ] && { echo "canary tripped at n=$n — results from here are noise"; exit 2; }
fi
```

Canary **every N requests**, not just at the ends — detecting a trip at request 25 instead of
request 497 is the difference between losing one batch and losing the whole run.

### Companion rule: wordlists read from `/mnt/c` or `/mnt/d` are CRLF until proven otherwise
```bash
file "$W"; head -2 "$W" | od -c | head   # look for \r \n
tr -d '\r' < "$W" | grep -v '^$' > /tmp/w.txt   # always normalise before use
```
The same trap bites `ffuf -w`, `-H` header files and any `while read` loop, and it fails *silently*
in the direction that looks like success.

### Companion rule: a background job's output file is not the job's result
Reading the output file of a still-running background task and acting on what is there is a
correctness bug, not an optimisation. In the engagement above, an empty-at-the-time output led to
"no wordlists exist" being recorded, and a clean negative was filed on a weaker basis than claimed.
**Wait for the completion event before recording any negative that depends on the job.**

---

## The general checklist (run it in this order, every time)

1. **Name the oracle.** What exactly are you reading — a status code, a body size, a resolution,
   a poll result, a file on disk? One sentence.
2. **State what a negative means.** "No hit = no SSRF" is only true if the detection chain works.
   Write down what a true negative would have to look like.
3. **Fire the control** — an input that MUST produce the opposite reading. Canary path for a
   fuzz run, absent key for an S403, minted-and-pinged payload for an OOB poll, uuid path for a
   bucket, fresh tempfile per request for file-based loops.
4. **Only then read the result.** If the control failed, discard the whole result set — both the
   negatives and the "hits" — and fix the instrument before re-running.

This is the same reflex as [[bypass-4xx]]'s decode control and [[parameter-deep-dive]] §0's
baseline: establish what "the instrument works" looks like before interpreting any reading.

## Signals that are never evidence on their own

None of these proves anything, in either direction, without a control:

- **A 200 on a wildcard host** — wildcard DNS + a catch-all app 200s everything; a "found page"
  may be the shell.
- **A 403 from a shared edge** — CloudFront/Akamai/WAF 403 is the edge talking, not the app;
  mid-fuzz it means *you are blocked*, not *the path is protected*.
- **A DNS resolution on a wildcard domain** — everything resolves; resolution carries zero
  existence information.
- **An empty OOB poll** — with an unpollable or unminted payload, "no interactions" is the
  default output of a broken detection chain, not evidence of no callback.
- **An unchanged response to an ignored parameter** — the app may not parse the parameter at all
  (the [[mass-assignment]] silent-200 trap, and [[bypass-4xx]]'s "encoding bypass that lands on
  404" are the same shape): read the control first.
- **An HTTP `000`** — the request was never sent (malformed URL, CRLF from a `/mnt/c` wordlist,
  DNS/TLS/proxy failure). It is neither a block nor a finding; a run containing any `000` is
  invalid until the tooling is fixed. See Case 6.

Before anything reaches `findings/`, it still passes [[validate]] — and a finding whose only
evidence was an uncontrolled oracle will not survive the validator's Q1.

---

## Case 7 — the throttle that masquerades as a discovery jackpot (inverse of Case 1)

**Where it bit:** `usermgmt.svc.acme.example` (the vendor), 2026-10-01.

Case 1 covers the familiar shape: a run of denials that *looks* like a ban. This is the mirror
image, and it is more dangerous because the failure mode is a wall of apparent **successes**.

The host is an AWS API Gateway custom domain. Unmapped base paths return
`403 {"error": {"code": "ERR_403", "message": "Access denied"}}` — **58 bytes**. A 58,723-word
first-segment `ffuf` run at 18 req/s tripped a throttle, after which every unmapped path returned
`429 {"error": {"code": "ERR_429", "message": "Too many requests"}}` — **62 bytes**. The run was
filtered with `-fs 58`. Result: thousands of "hits", every single one a throttled response, output
that reads exactly like finding an undocumented API.

### Why the usual canary did not save it
The canary was `GET /ping`, a *mapped* route — and the throttle applied only to the **unmapped (403)
path tier**, so `/ping` kept answering `200 healthy` right through the poisoned run and for the 20+
minutes the throttle persisted afterwards. A canary on a route that is *reachable* proves the host is
up; it does not prove that the tier you are enumerating is still answering truthfully.

### The control
Fire **two** post-run canaries, not one:

```bash
# 1. a KNOWN-GOOD path   -> proves the host is not banned
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://target/ping
# 2. a KNOWN-BAD path    -> proves the DENIAL TIER is still answering with the denial you filtered on
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://target/zzrandctl
```

If canary 2 no longer returns the baseline denial, **discard the entire run**. Do not cherry-pick.

### Two durable rules
1. **Never size-filter an enumeration whose denial body is a short JSON error.** Throttle, auth and
   not-found envelopes from the same gateway differ by a handful of bytes, and any of them can
   replace your baseline mid-run. Filter on content: `-fr 'ERR_403|ERR_429'`, or `-fc` on the status.
2. **Baseline the error *bodies* you expect to see, before the run**, not just the one you intend to
   filter. Fire the known-bad path, the rate-limited path (hit it deliberately a few times at the
   start if you can afford to), and an auth-required path; record all three sizes. Then you can tell
   which envelope a "hit" actually is.

---

## Case 8 — your intended positive control is defeated by validation-before-authz

**The failure.** On `mesh.svc.acme.example` the MSP invite-accept route is
`PATCH /members/invitations/{id}` with body `{action, token}`, where `token` is a signed invite JWT
whose claims carry the authorization decision (`role`, `mspId`, `recipientEmail`). Four forgeries
were fired — signature byte-flipped, `alg:none`, `alg:none` + `role` escalated to `owner`, and
signature stripped entirely. All four returned `401 member_invite_token_invalid`.

Four 401s prove nothing on their own. The endpoint could 401 everything. A **positive** control was
needed: evidence that a *genuine* token is treated differently. Firing the real token with
`action: accept` would consume a single-use invite, so the clever-looking move was to send the real
token with a deliberately invalid `action` — expecting a complaint about `action` to prove the token
had been verified.

It proves nothing. Both of these return the identical response:

```
real token    + action:"bogus"  ->  400 "body.action must be one of: accept decline"
tampered token + action:"bogus" ->  400 "body.action must be one of: accept decline"
```

**Body validation runs before token verification.** The token is never examined, so the error is
blind to whether it was real. The "control" discriminated nothing — it was a second negative
wearing a positive's clothing.

### The rule

A positive control must exercise **the exact code path** whose behaviour you are claiming. If any
earlier-stage check (schema validation, content-type, CSRF, rate limit) can short-circuit the
request, your control measured that earlier stage instead. Before trusting a control, ask: *which
check produced this response?* If two inputs you believe differ produce byte-identical responses,
the control is dead — say so in the finding rather than quietly banking the negative.

This is the mirror of the 400-vs-403 validation-before-authz trap in
[[framework-misconfig]]: there it masks an authz gap, here it masks the absence of a control.

### What to do when the positive control is unreachable

Record the gap explicitly instead of implying the negative is airtight. The honest shape:

> The four 401s are trusted on the strength of the garbage-token control and the differential error
> codes. The acceptance path was never fired because doing so consumes a single-use invite, so a
> positive "real token accepted" observation is still missing. **Residual risk: low but non-zero.**
> Close it on the next invite received.

A clean negative with a named hole is worth far more than one that hides it — the hole is the next
run's first task.

---

## Case 9 — a later-stage error is a free read-only oracle (use it deliberately)

The inverse of Case 8, and a genuinely useful technique rather than a trap.

**The situation.** `POST /api/fabrics/base/msp/v1/idp` takes `consentRedirectUrl` and, on success,
**creates state** (a PENDING IdP binding). Mapping how wide its URL allowlist is would normally
mean creating and deleting a binding per probe — slow, and it writes to the tenant every time.

**The shortcut.** Once one binding exists, the endpoint returns
`409 idp_binding_already_exists`. Crucially, URL validation runs *before* that existence check,
which the response codes prove:

```
http://account.acme.example/x        -> 400 invalid url      (scheme rejected)
https://account.acme.example:443/x   -> 400 invalid url      (port rejected)
https://account.acme-legacy.example/x     -> 400 invalid url      (TLD rejected)
https://attacker.acme.example/x      -> 409 already exists   <- PASSED validation
https://sso.acme.example/x           -> 409 already exists   <- PASSED validation
```

So with a binding deliberately left in place, **409 means "your value was accepted by the
validator"** and 400 means it was not — a boolean oracle that performs no writes. The whole
allowlist was mapped in one pass, then confirmed on a clean slate with the single pair that
mattered (`attacker-controlled.acme.example` -> 201 vs `example.com` -> 400).

### The rule

When an endpoint has a later-stage guard you can hold open (already-exists, conflict, quota
reached, wrong state), it converts a state-changing endpoint into a read-only probe for every check
that runs *before* it. Establish the ordering first — demonstrate that at least one input reaches
400 and another reaches 409 — because the oracle is only valid if validation genuinely precedes the
guard. Then confirm the one or two conclusions that matter on a clean slate, so the finding does
not rest on the oracle alone.

Corollary for hygiene: whatever state you created to hold the guard open, **delete it and
re-verify the original state**. On the run above, three PENDING bindings were created and deleted
(`DELETE /idp` -> 202), with `GET /idp` -> `404 idp_binding_not_found` confirming the tenant matched
how it was found.

---

## Case 10 — an oracle is a property of the host, not of the technique

`OPTIONS` on `designer.svc.acme.example` is a real route/method oracle: it returns 200 and the exact verb
for routes that exist, and **404 `errors.route.notFound`** for ones that do not. That control is
what made it a finding rather than a blanket 200.

The same probe on `mesh.svc.acme.example` returns **200 for every path**, including
`/members/invitations/zzz-not-real-route`. There is no discrimination, so there is no oracle — and
any "this route exists" conclusion drawn from it would have been fabricated surface.

### The rule

Never carry an oracle across hosts, even inside the same estate and the same `.svc.acme.example`
namespace. Fire the absent-path control on **every host** before using the technique there. This
estate already proves the point twice over: CloudFront distributions that answer oppositely on
encoded paths (`idp` decodes, `design.dev` does not), and now OPTIONS. The technique is portable;
its validity is not.

---

## Case 11 — the denial SHAPE is per-service, so one oracle table silently misreads half the estate

Observed on an enterprise-identity gateway (`/gw/<service>/api/v*/`) where every response is
HTTP 200 and the real verdict lives in a JSON `code`. One service leaked the enforced RBAC
permission name on every denial, so the whole engagement was graded against that one contract — and
four other services turned out to speak different dialects entirely:

| Denial shape | What it actually means | How it misreads |
|---|---|---|
| `E_X_UNAUTHORIZED` + msg = `pay.subscription.view` | per-route permission, name leaked | the contract everyone assumed was universal |
| `E_X_UNAUTHORIZED` + msg **EMPTY**, *including for routes that do not exist* | **authz evaluated BEFORE routing** | you cannot test route existence here at all, and you get no permission intel |
| `E_X_APP_UNAUTHORIZED` + `permission deny` | different service, different namespace | a `grep E_X_UNAUTHORIZED` sweep scores this as OTHER and drops it |
| numeric `{"code":606,"message":...}` — key is **`message`**, not `msg` | separate auth service with its own contract | a parser keyed on `msg` reads it as "no code field" = NON-JSON = ignored |
| `E_X_RESOURCE_NOT_FOUND` / `E_X_<X>_NOT_FOUND` | reached the handler, authz passed, the ID was wrong | **scored as a failure when it is actually the most interesting result on the host** |

### The rule
**Before grading a multi-service estate, enumerate the denial dialect of each service separately.**
One request per service does it: fire a route you know you cannot have, and a route you know is
absent, and write down both shapes.

```bash
for svc in identity billing authn notifications access-control support reporting audit-log messaging feedback; do
  printf '%-14s ' "$svc"; ./probe.sh member GET "/gw/$svc/api/v1/zzznope_$RANDOM"
done
```

Two corollaries that each flipped a result on that engagement:

- **A `NOT_FOUND` for the low-priv role is not a denial — it is authz silence.** Check the same id as
  the privileged role: if the privileged role *also* gets NOT_FOUND, the id namespace is simply wrong
  and there is no bug (this killed two leads). If the privileged role can READ it, the low-priv role
  passed authz and was stopped only by not knowing an identifier — that is an authz gap whose
  exploitability is now a key-discovery problem, which is a very different report.
- **A single catch-all error destroys the existence oracle for that whole subtree.** Three services
  returned an identical 39-byte `E_C_INVALID_REQUEST` for absent routes *and* for real routes called
  with bad params. Every "route not found" conclusion in those subtrees is noise; the only way in is
  a route literal recovered from the client bundle.

### Case 11 addendum — the dead session that does not look like one

The canary rule exists for this, but the *shape* of the failure is what makes it dangerous. On the
enterprise-identity estate an expired session did **not** return the documented unauthenticated error
(`E_X_ACCESS_TOKEN_INVALID` / "The access token is missing"). It returned a different, entirely
plausible-looking code — `E_X_INVALID_SESSION` / "Invalid Session", 54 bytes — on **every** route.

Fired against a surface of unmapped services, that reads exactly like "these services reject the
portal session", which is an interesting-sounding architectural conclusion and completely false. It
cost a run its last three result sets, including a 110-request clean negative that had to be
retracted.

Two rules, both cheap:

1. **Fire the KNOWN-GOOD canary every ~40 requests, not only at the start and end.** One request per
   40 buys you a bounded blast radius; the alternative is knowing the run is partly void and being
   unable to say which rows.
2. **A uniform new error code appearing across many services at once is a session/edge event, not a
   discovery.** Before writing it up as a property of the target, re-fire the canary. If a conclusion
   would be "all these services behave identically in a surprising way", suspect your own session
   first.

And when it does happen: **retract the affected results explicitly in the coverage file**, naming
which ones and why, rather than quietly re-running. A retracted clean negative that a later session
can see was retracted is worth more than a silent re-test, because the next run otherwise inherits
a result nobody can date against a canary. See [[engagement-ceiling]] on stating what a limitation
caps.

---

## Case 6 — DNS 0x20 case randomisation looks like payload tampering (it isn't)

**Symptom.** A Collaborator/interactsh DNS entry shows your hostname with scrambled capitals:
`usercheck.<your-collab-id>.oastify.com` — even though you sent all lowercase.
Easy to read as "something server-side rewrote my payload" or "this came from a different
origin", and easy to waste an hour on.

**Cause.** **DNS 0x20 encoding** (a.k.a. DNS 0x20 bit / case randomisation): the *recursive
resolver* randomises the case of each label in the query, and the authoritative server must echo
it back byte-for-byte. A mismatch means the answer was spoofed, so it is a cheap anti-cache-
poisoning defence. Google Public DNS and many ISP resolvers do it. It is applied **in transit by
the resolver**, so it says nothing about who originated the lookup.

**Control that settles it in one shot** — fire an all-lowercase probe from your own client and
compare:
```bash
curl -s -o /dev/null "http://0x20demo.<your-payload>.oastify.com/case-test"
# then poll; note the DNS clientIp
dig +short whoami.akamai.net        # reveals which recursive resolver you egress through
```
Same resolver IP on the scrambled-case entry and on your known-own probe ⇒ resolver behaviour,
case closed.

**Attribute OOB hits on these instead of case** (record all three at the start of every
engagement — see Case 4):
1. **Egress fingerprint.** Log your own DNS egress and HTTP egress IPs from the pre-control.
   A real server-side fetch arrives from the target's hosting range (e.g. a Google Cloud IP for a
   GCP-fronted API), never your residential/ISP egress.
2. **User-Agent on the paired HTTP hit.** `curl/8.x` or your browser = yours. A genuine SSRF shows
   the backend's client (Go-http-client, Java/OkHttp, python-requests, axios/node).
3. **Unique label per injection point.** One DNS label per test (`xfh`, `placeid`, `cq`, …) so any
   hit self-identifies. Keep oracle/pollability labels (`pre`, `usercheck`) visually distinct from
   test labels — then a control hit can never be mistaken for a finding.

**Bilt engagement, 2026-10-13:** two interactions on a pasted payload were briefly read as an SSRF
hit. They were the pollability probe: label `usercheck`, path `/oracle-check`, `curl/8.12.1`, own
egress `163.121.128.152` (DNS) / `197.45.64.182` (HTTP). The mixed case was just TE Data's
resolver doing 0x20. The egress fingerprint taken during the pre-control is what made the call
instant instead of speculative.

---

## Case 12 — a pinned-trust client with `root: null` for an env FAILS CLOSED, so "verification disabled" is almost always backwards

**Where it bit:** `records.acme.example` (the camera/NVR product Verify, 2026-10-14). The client bundle shipped an
env map for a cryptographic chain-of-custody verifier:

```js
const Pk = {
  prd: { origin:"https://surveil.svc.acme.example",     root: H2   },
  stg: { origin:"https://surveil.stg.svc.acme.example", root: j2   },
  dev: { origin:"https://surveil.dev.svc.acme.example", root: null },   // <-- looks catastrophic
  qa:  { origin:"",                               root: null },
  mock:{ origin:"",                               root: Z2   }    // rootKeyId "mock-evidence-root-v1"
};
```

A whole hunting shard was commissioned on the reading *"dev has no pinned root, therefore signature
verification is disabled in dev, therefore dev is where a forged video verifies as authentic."*
That reading was wrong, and reading **four more lines** of the resolver killed it:

```js
function e0(){
  const l = G2(), { origin:a, root:n } = Pk[l];
  if(l !== "mock"){ if(!a) throw new Error(`registry env "${l}" has no origin configured yet`); K2(a); }
  if(!n) throw new Error(`registry env "${l}" has no pinned trust root yet — verification is unavailable`);
  return { env:l, origin:a, root:n };
}
```

`root: null` throws **before** any URL is built. The env yields *"cannot verify"*, which is the
opposite of *"verifies anything"*. A missing key in a pin table is a hole only if the consumer
**skips** the check on absence; far more often it short-circuits, because that is the easy way to
write it.

### The rule — two greps before you believe a config-shaped jackpot

1. **Find the resolver, not the table.** A `null` / `""` / missing entry is a LEAD about the
   *table*. The finding lives in the code that consumes it. Trace the table through to its reader
   and look for `if(!x) throw` / `return false` / `fail-closed` before anything else. This is the
   same discipline as `auth:false` in a route table being a lead and never a finding
   (`SKILL.md` anti-false-positive rule 2).
2. **Check whether the env is even selectable at runtime.** A Vite/webpack build inlines
   `import.meta.env.VITE_*` as a string literal, so the shipped bundle contains the *answer*, not the
   lookup:

```bash
# the env is a build-time constant if G2()/equivalent returns a literal and ALL of these are 0
for t in 'import.meta' 'searchParams' 'location.search' 'localStorage' 'sessionStorage' 'window.__'; do
  printf '%-18s %s\n' "$t" "$(grep -o -F "$t" bundle.js | wc -l)"
done
# 0 across the board = there is NO query param, cookie, storage key or global that repoints
#                      the production client at dev/stg/qa/mock. The alternate env is unreachable.
```

In the case above all six were `0`, and the only two occurrences of `VITE_REGISTRY_ENV` were inside
error strings. Bonus: the same resolver explicitly refused the one env an attacker actually wants
(`if(l === "mock") throw` — `mock-evidence-root-v1` implies a published/test private key).

**Corollary for pre-prod hunting generally:** before investing in a dev/stg sibling, establish that a
*client* can be pointed at it. A reachable pre-prod backend that no shipped client will ever talk to
is a self-XSS-grade finding at best.

---

## Case 13 — the S3 no-ListBucket key-existence oracle (`200`/0 B vs `403 AccessDenied`)

**Where it bit (usefully):** `cdn.pkg.svc.acme.example`, the appliance OS application-package CDN, 2026-10-14.

An S3 origin with object-read but no `s3:ListBucket` for anonymous callers answers `403
AccessDenied` for keys that **do not exist** and `200` for keys that **do**. That turns every path
into a yes/no question even though listing is refused:

```bash
curl -s -o /dev/null -w '%{http_code}/%{size_download}\n' https://cdn.example.com/acme-surveil-ui/  # 200/0   -> EXISTS
curl -s -o /dev/null -w '%{http_code}/%{size_download}\n' https://cdn.example.com/zzznope/           # 403/111 -> absent (control)
curl -s                                                   'https://cdn.example.com/?list-type=2'     # 403     -> listing refused
```

`200` with `Content-Length: 0` is a zero-byte "folder marker" object — real, and proof the prefix
name is right.

### Rules
- **The control is mandatory and free:** fire a deliberately absent sibling prefix in the same loop.
  Without it you cannot distinguish "exists" from "this bucket answers 200 to everything".
- **Grade it honestly.** Enumerating *product* names is Low/Info. It becomes a real finding only if
  a prefix is **per-tenant or per-user** — then the same oracle is a tenant/customer enumerator.
  State which one you proved.
- **Its real value is usually as an unblocker, not a report.** Here it was the cheapest route to an
  offline source read for a device-plane auth scheme that production 400-gated. One version string
  turns a confirmed prefix into an anonymously downloadable package.
- Distinguish from the two neighbours: `403 AccessDenied` on the bucket root = public-read prefix
  with no listing; `404 NoSuchKey` = the bucket DOES grant `ListBucket` (then just list it).

---

## Case 14 — the multi-header gate: a header battery that tests one header at a time is a FALSE NEGATIVE

**The trap.** You probe an auth gate by sending candidate header names one at a time, 24 of them, and
every single one returns the identical error. You conclude "no name-guessing oracle exists — this must
be mTLS or a signed credential terminated upstream" and you close the lane.

**What actually happened** (`surveil.svc.acme.example`, two shards of the same service, 2026-10-14):
the gate wanted **two** headers and checked for *both* before reacting to *either*.

```
GET /api/v2/records/exports                                       -> 400 "missing device ID or device auth"
GET /api/v2/records/exports  + x-device-auth   (alone)         -> 400  unchanged   <-- shard A stopped here
GET /api/v2/records/exports  + x-device-id     (alone)         -> 400  unchanged
GET /api/v2/records/exports  + x-device-id + x-device-auth  -> 401 "device auth not found"   <-- the real answer
```

Shard A had `x-device-auth` in its battery and still recorded the class as un-fingerprintable,
because the partner header was never paired with it. The scheme turned out to be a plain static
two-header bearer pair — no mTLS, no signing, no nonce. The wrong conclusion survived two lanes.

**The tell you must not ignore: read the error string as a specification.**
`missing device ID or device auth` names **two** credentials. An error that enumerates N credentials
is telling you the gate is an N-ary AND. The same applies to `missing session or csrf token`,
`missing key id or signature`, `missing tenant and actor`. One-at-a-time probing of an N-ary gate
returns the baseline error N times and reads as a clean negative.

**The control.** Before recording any header-gate as un-fingerprintable:

1. **Parse the error message for every noun it names** and probe the full combination, not the
   singletons. With 2-3 candidates per noun this is a handful of requests, not a matrix.
2. **Prove the gate can move at all** — find any input that changes the response. If nothing you send
   ever changes the message, you have not demonstrated "no oracle"; you have demonstrated that you
   never reached the check. Those are different findings and only one of them is true.
3. **Then test the discriminators**, which is what makes the result trustworthy rather than lucky:
   - each header alone -> baseline error (proves both are required);
   - the right partner swapped for a near-miss name (`x-device-auth-token` vs
     `x-device-auth`) -> baseline error (proves it is *that* header, not merely "two headers");
   - empty value on either -> baseline error (proves non-empty is required);
   - several value shapes (1 char / 12-hex / 32-hex) -> all the same advanced error (proves there is
     no format constraint, so a later negative is not a format rejection in disguise).
4. **Canary-bracket it like any other batch** — known-GOOD and known-BROKEN request before and after,
   so a `400`->`401` transition cannot be an edge artefact.

**Where the names come from, cheaply.** Do not brute-force header names. Appliance and SPA bundles
ship a flat `HeaderNames` enum; one `grep` recovers the vendor's entire custom-header vocabulary at
once — in this case `x-device-id`, `x-device-auth`, `x-device-auth-token`,
`x-device-application`, `x-device-peer-mac`, `x-shared-case-password`, `X-Internal-Use`, `X-ApiKeyId`. See
`js-analysis.md` § "Reading a one-line multi-megabyte webpack bundle" and
`framework-misconfig.md` § "Vendor package index".

**Grading rule.** A header-gate negative is only trustworthy if the write-up records: the nouns in
the error string, the combination probed, the per-header-alone result, the near-miss-name result, and
the canary bracket. Absent those, write `CEILING`/`BLOCKED`, not `CLEAN`.

---

## Case 20 — The 503/5xx window poisons a whole batch, and it looks exactly like a clean negative

**Where it bit:** `console.svc.acme.example`, 2026-10-15. A batch covering XXE, content-type confusion,
duplicate-key HPP and 404-path reflection came back entirely `403`/`503` from nginx. Read naively
that is "edge blocks everything, class clean". In fact the **whole host** was down —
`GET /api` itself returned `503 Service Temporarily Unavailable` for ~5-10 minutes before
self-recovering. Every result in that batch was infrastructure noise.

**Control:** your GOOD canary must be fired *inside* the batch, not only at its ends, and it must be
a **200-class** route, not a 401 route — a 401 and a 503 are both "not 200" and a tired reader
conflates them. Pattern that works:

```
GOOD-200  GET /api                     -> 200 {"app":"..."}            # host is serving
GOOD-401  GET /api/users/me            -> 401 {"statusCode":401,...}   # app logic is running
BAD-404   GET /api/nonexistent-xyz-9182-> 404 "Cannot GET ..."         # your requests are well-formed
```

If GOOD-200 is not 200, **discard the batch and re-fire after recovery** — do not cherry-pick the
rows that look like hits, and do not record the classes as clean. Mark them UNREACHED, which is a
different thing and tells the next run to re-run them.

**Second-order lesson:** note what you were doing immediately before the window. Here it was a
handful of socket.io/engine.io connects, twice, both times followed seconds later by the 503. That is
a correlation worth *writing down and not confirming* — confirming it means deliberately degrading a
production API. Flag it, hand the RoE decision up, and stop touching that transport in volume.

## Case 21 — When the unknown-route response equals the auth-gate response, route existence is unknowable

**Where it bit:** `returns.svc.acme.example` and `assetsvc.svc.acme.example`, 2026-10-15.

```
returns.svc       GET /zzz-nonexistent-9182  -> 401 {"errors":[{"status":"401","title":"Unauthorized"}]}
returns.svc       GET /join/<hash>           -> 401  (identical)
assetsvc.svc  GET /                      -> 404 Not Found      # note: inverted
assetsvc.svc  GET /zzz-nonexistent-9182  -> 401 Unauthorized
```

The gateway answers `401` for paths that do not exist. So a `401` on a route you mined from a bundle
proves **nothing** — not that the route exists, not that it is auth-gated. Any "N routes confirmed
present behind auth" claim built from 401s on such a host is void, and an entropy or
existence-oracle question on one of those routes is **unanswerable**, not open.

**Control:** always fire the BAD canary *on that host* and compare it to your target response before
you interpret a single 4xx. Hosts in the same estate differ — `console.svc` returns a framework
`404 "Cannot GET /api/..."` for unknown paths and a `401` only for real gated routes, so the same
inference is valid there and void one hostname over. Per-host, every time.

### Case 6 companion — curl URL-globs `[]` and `{}`: a silent never-sent probe that looks like a WAF block (acme.example br.store.acme.example, 2026-10-15)
An SSR-query-param matrix fired three probes containing literal `[]` / `{}` in the query
(`?embed_return_url[1]=x`, `?appview={{7*7}}`). All three returned **no HTTP response at all** —
curl's URL globbing consumed the brackets/braces client-side and the requests were never
constructed; the harness printed empty rows that sit ambiguously between "blocked" and "untested".
The canaries stayed green throughout, so nothing tripped — this failure mode is invisible to the
canary by design (nothing was sent).

**Rule:** any probe URL containing `[`, `]`, `{` or `}` must be fired with `--globoff` (or
percent-encode the metacharacters first, e.g. `%5B`, `%7B`), and a harness must treat a missing
status line / 0-byte body as VOID-AND-REFIRE, never as a row. Three voided rows here were re-fired
encoded and reached the origin normally; the unencoded firings were discarded. Same family as the
`000` mirage above: **a request that never left proves nothing in either direction.**

---

## Case 21b — a `401` proves existence ONLY where no sibling `:param` route can swallow the path

Refinement of Case 21 (per-host existence inference), measured on `console.svc.acme.example` (NestJS behind a
global guard) on 2026-10-15. Case 21 says inference is valid on that host because an unknown route
returns `404 "Cannot GET /api/..."`. True — but the granularity matters, and getting it wrong
manufactures routes that do not exist.

```
GET  /api/backorders-zzz9182                   -> 404 Cannot GET      # inference VALID
GET  /api/ordersZZ                             -> 404 Cannot GET      # inference VALID
PUT  /api/quotes/{uuid}/enable-checkout-zz      -> 404 Cannot PUT      # inference VALID
POST /api/quotes/{uuid}/sync-reward-zz          -> 404 Cannot POST     # inference VALID
  — but —
GET  /api/clients/csv-zzz9182                  -> 401 Unauthorized    # absorbed by GET /api/clients/:clientId
GET  /api/backorders/zzz9182                   -> 401 Unauthorized    # absorbed by a sibling :param route
```

**Rule:** before claiming a route exists because it returned `401` instead of `404`, fire the same
path with the *final literal segment* mutated (append `-zz`). If the mutant also returns `401`, your
probe is matching a wildcard parameter route and proves nothing about the name you were testing. A
single-segment probe directly under a collection prefix (`/api/<collection>/<anything>`) is
indistinguishable from `:id` and is never an existence proof.

Corollary that pays: this control is cheap enough to fire per claimed route, and it is what lets you
assert "this undocumented admin route exists in production" from a source-map name — on the vendor
run it confirmed `PUT /api/quotes/{id}/enable-checkout`, `POST /api/quotes/{id}/sync-reward`,
`PUT /api/orders/{id}/refetch` and `GET /api/backorders` as real, while simultaneously showing
`POST /api/users` is **absent in production** despite being called from the onboarding source. Source
reference is a lead; the `-zz` control is the evidence.


## Case 22 - the edge TRIP THRESHOLD is a number, and it is lower than your wordlist

Measured on the vendor estate across four independent lanes, 2026-10-17. Four independent lanes hit
WAF/rate bans and all four reported the same shape:

- **Per-host trip threshold is roughly 1,200-2,100 requests at `-rate 6`.** Confirmed by L26
  (429 after 1,307 requests on one host and 2,131 on another) and by L22 (429 on its first ffuf run
  at `-rate 8`).
- **Some distributions ban at `-rate 2`.** L28 was banned on `feedback.svc` at rate 2, and got a
  full-path `403/919` latch on `blobstore.svc` plus a `429` on `notify.svc`.
- **Bans are per-distribution, not estate-wide**, and the window is about **10-15 minutes**. Verify
  with a 1-request-per-host egress-health sweep before resuming.

**What this means for planning, and it is the important part:** an 82k wordlist at a safe rate is
**3.8-5.7 hours per host**. A multi-host full-depth pass is not slow, it is *arithmetically
impossible* inside one lane, and the target will ban you before you finish anyway. So:

- Budget **<= rate 4**, and split batches at **~800 requests per host**.
- Prefer a **high-signal slice** (a few thousand curated entries) over a full list. On this estate
  the curated passes found everything the full passes would have, because the full passes could
  never run.
- **A ban poisons every negative produced in that window.** Discard the batch (Case 20), cool down,
  re-verify with canaries, and say so in the report. L28 correctly **withdrew** the negatives for
  three poisoned hosts rather than banking them.

## Case 23 - `ffuf -ac` can silently discard every real hit

On a gateway that returns a constant body for unknown routes, `ffuf`'s auto-calibration baselines
against that constant and then filters out **everything that matches it, including real hits**.

Measured on one of those lanes: with `-ac`, the deliberately-planted `talk` positive control returned
**0 results**. The lane replaced `-ac` with a verified **`-fc 404`** per-service status filter and
the control reappeared 10/10.

So: when auto-calibration is on, **plant a positive control you know must be found and confirm it
survives**. If it does not, `-ac` is lying to you - switch to an explicit `-fs`/`-fc` derived from
your own Phase-0 oracle table.

## Case 24 - session SHAPE matters: `cookie_form` vs raw JWT

Two lanes the same day (L24, L26) independently found that on this estate a stored
`cookie_form` value is **rejected**, while the same credential sent as a raw JWT
(`Cookie: VENDOR_SSO_AUTH=<jwt>`) is accepted.

This produced a **false blocker**: one lane reported "no live identity - A and D both 401 at sso",
skipped its entire authenticated parameter and two-account workload on that basis, and was
**wrong** - both sessions were verified live minutes later by the orchestrator using the raw-JWT
shape.

**Rule:** a 401 is not proof a session is dead. Before declaring an identity blocked, re-try the
other credential shape, and name the shape you used in the report.

---

## Case 25 — the empty-collection vacuous success (a write that is not a write)

**Where it bit:** the enterprise-identity product tenant, `PUT /gw/access-control/api/v1/admin/credential/unbind`.

A zero-privilege principal sent the SPA's own captured body:

```
PUT /gw/access-control/api/v1/admin/credential/unbind
{"card_id":[]}
-> {"code":1,"error_params":null,"msg":"success"}
```

That reads as a clean vertical privesc on a physical-access-control admin route. It is not. The
**same route, same principal, with a forged card id**:

```
{"card_id":["00000000-0000-0000-0000-000000000000"]}
-> {"code":"E_X_UNAUTHORIZED","msg":"you are not authorized to perform \"access.credential.edit\" operations"}
```

The empty list means the handler has nothing to iterate, so it returns success **before** ever
reaching the per-object authorization check. Authorization is enforced; the success was vacuous.

**The rule:** an empty array, empty object, empty string or absent-value write that returns
success is **never** evidence of authorization. Re-send every such test with a well-formed,
non-empty, plausible value before believing anything. An empty collection is a false-positive
generator, and SPAs send them constantly (a cleared form, a deselected list), so they appear all
over captured traffic and look authentic.

This is the write-side sibling of the validation-before-authz trap in `bypass-4xx.md`: there a
`400` hides the authz decision; here a `200` does.

**Generalise it — the three ways a 200 lies on a write:**

| shape | why it returns success | how to kill it |
|---|---|---|
| empty collection | nothing to process, authz never reached | resend with one real element |
| idempotent no-op | the target already has the desired state | pick a target in the opposite state |
| fire-and-forget / queued | accepted for async processing, authorized later | read back after a delay |

**Always prove a write by reading the object back, and read it back as a DIFFERENT principal**
(ideally the owner) so you are observing committed state rather than your own request echo.
On the engagement above this is exactly what separated the real finding from the false one:

- `credential/unbind` + empty list -> success, **no state change** -> discarded, authz enforced.
- `idp/app/assign_apps` + a real `app_id` onto a worker whose app set was `[]` -> success, and
  the owner's read-back showed the app present -> **confirmed unauthorized write** (High).

## Case 26 — an equal-privilege second principal is what makes an authz finding airtight

Same engagement. Three principals, and the third one is what turned a decent finding into an
airtight one:

| principal | standing | the leak route |
|---|---|---|
| A | tenant owner | `SUCCESS` (expected) |
| D | zero privileges, **cloud/admin-portal** credential | `SUCCESS` <- the gap |
| E | zero privileges, **user-portal** credential | `E_X_APP_UNAUTHORIZED "permission deny"` |

D and E were proven equal in privilege first, by showing both receive byte-identical refusals on
two unrelated services (`permission.access_policy.view`, `esm.software_report.enable`). Only then
does the divergence mean anything.

**Why this matters.** With A and D alone the finding invites the strongest possible rebuttal:
*"there is no authorization model on that service."* E's refusal proves the check **exists, is
implemented, and returns a specific authorization error** — it is simply not consulted on the
other credential path. The finding stops being "authz is missing" and becomes "authz is
implemented and bypassed", which is both more credible and more actionable for the vendor.

**Operational rule:** when you have one unprivileged principal, get a second one that is
unprivileged *in a different way* — a different credential type, portal, login path, device or
onboarding route. Then:

1. Prove the two are equal in privilege on routes **unrelated** to your target, using the
   platform's own refusal messages as the measure.
2. Run the target route from both.
3. A divergence localises the bug to the credential path, not the permission model.

Corollary — the same evidence **kills** the adjacent false lead. The header that selects the
credential (`X-Tenant-Session-App` here) looked like a privesc, because flipping it changed what the
caller could reach. It is not: E flipping it to the admin value gets `E_X_INVALID_SESSION`,
because E holds no cloud session. A credential **selector** can only select among credentials you
already possess. Test the flip from a principal that lacks the other credential before reporting
one, or you will report a non-finding.

**The gateway's refusal message is itself the best reconnaissance on a permission-based API.**
Routes that deny you by name hand you the privilege model for free:
`esm.software_report.enable`, `permission.access_policy.view`,
`permission.access_policy.assign.self`, `access.credential.edit`. Harvest every one into a
route -> required-permission table. Each named privilege is a capability that exists somewhere,
and the routes that *should* name one but do not are exactly where the missing checks live.

---

## Case 27 — read the caller's ACTUAL entitlements before claiming it is unprivileged

**Where it bit:** the enterprise-identity product tenant. Cost two written-up findings and one H1 report
that had to be retracted after the PoC was already staged in Burp.

I built an authorization finding on the premise that a principal held "zero privileges". The
evidence for that premise was that it was refused on two routes:

```
GET /gw/device-mgmt/api/v1/admin/software/config
  -> E_X_UNAUTHORIZED "Roles do not have required privileges: [esm.software_report.enable]"
GET /gw/permission/api/v1/permission/group/of_worker/<id>
  -> E_X_UNAUTHORIZED "this user has no privileges: permission.access_policy.view"
```

Two refusals, so: unprivileged. Then it performed a write, the read-back confirmed the write
landed, and that looked like a clean missing-authorization finding with a proven state change.

It was not. The platform exposes the caller's own entitlements on request:

```
GET /gw/ent/api/account/info  ->  data.privileges[]
```

and the "unprivileged" principal held **59** of them, including the exact capability I had just
"exploited":

```json
{"privilege_const_key": "apps.applications.assign",
 "privilege_condition_const_key": "only_if_current_user_is_assigned_apps",
 "resource_ids": ["2e9ab254-…"]}
```

The write was its role working as designed.

**The reasoning error, stated precisely.** A refusal on route X proves the caller lacks privilege
X. It says nothing about privilege Y. I also claimed two principals were "equal in privilege"
because both were refused on the same two routes — but those routes test two *different*
privileges, and both principals lacking them says nothing about the rest of their sets. Measured:
59 privileges versus 25. The second principal held no `apps.*` privilege at all, which is why it
was refused where the first succeeded. The divergence I had attributed to a credential-path
bypass was simply two different roles behaving correctly.

**The rule:** before writing up any authorization finding, establish the caller's entitlements
*positively*. Most permission-based platforms will tell you: a `whoami`, `/account/info`,
`/me`, `/session`, a JWT claim, a `privileges` or `permissions` array, a GraphQL `viewer`. Find
it in the bundle if it is not obvious. Inferring "unprivileged" from refusals is inference from
absence, and it is the cheapest possible way to burn a report and your credibility with a
programme.

### The question to ask once privileges are resource-scoped

When an entitlement carries a condition and a resource list, "does the caller hold the privilege"
is usually the wrong question. The right one is **"does the server enforce the scope the privilege
declares?"** On this target that reframing is what rescued a real finding from the wreckage:

| path | out-of-scope attempt | result |
|---|---|---|
| assign (write) | `app_id` outside `resource_ids` | `E_C_PARAMS_INVALID`, no state change — enforced |
| revoke (write) | `app_id` outside `resource_ids` | `E_X_APP_UNAUTHORIZED "not assigned app manager to you"` — enforced |
| app detail (read) | `app_id` outside `resource_ids` | full configuration returned |
| roster (read) | any `app_id` | entire company directory with emails + ids |

Writes honoured the scope; reads ignored it. Same service, same privilege data, one check
present and one absent — a far more precise and more defensible finding than the one I started
with, and it survived because the *scope* was tested rather than the *privilege*.

**Design the discriminator around the scope boundary.** Create an object that sits wholly
outside the caller's declared scope — here, a worker holding *only* an application the caller
does not manage — and compare the caller's read against the owner's. Identical responses prove
the scope is not applied. Without that object you cannot distinguish "scope ignored" from
"scope happens to overlap", and a finding built on the overlap is a false positive waiting to be
found by the triager instead of by you.

**A corollary on the value of a second principal.** Case 26 recommends getting a second
unprivileged principal to prove a check exists. That still holds, but Case 26 as originally
written leaned on two principals receiving matching refusals as evidence they had matching
privileges. They did not. A second principal is useful for showing *that* a check fires; it
establishes nothing about *why* it fired for one caller and not another until both entitlement
sets are read and diffed. Read both sets. The diff is the evidence; the matching refusals were a
coincidence of two roles each lacking one unrelated privilege.

---

## Case 13 — the wrong identifier makes a broken test look like a clean negative

A two-account authz matrix where **every** arm returns 403 is not a negative. It is ambiguous, and
the likeliest explanation is that your test is broken.

Real example: a tenant API gated by a workspace-selector header. The matrix read

```
B + hdr = A's workspace   -> 403 no permission      (foreign: expected)
B + hdr = B's workspace   -> 403 no permission      (own: ???)
B + hdr = bogus uuid      -> 403 no permission      (control)
```

and was written up as "the header is enforced and leaks nothing — it refuses foreign and bogus
alike". The own-workspace row was the tell: **B should succeed against its own workspace.** The
value being used for "B's workspace" was wrong — copied from stale notes, one hex digit family off —
so that arm was a *third* bogus-id test. Re-run with the id resolved from the API, B returned **200**
with its own (empty) collection, and the negative became properly supported.

### The rule

**Every authz matrix needs a cell that SUCCEEDS.** If the principal under test never gets a 200
anywhere, you have not shown that authorization works; you have shown that your principal, session,
header or identifier is broken. A session that is refused everywhere refuses for free.

### Resolve identifiers from the API, never from notes

Ids drift across a long engagement: records get deleted and recreated, memberships are torn down and
rebuilt, and summaries get recopied. Before any cross-account run, re-resolve each principal's ids
from the service itself and prefer the endpoint that marks the caller:

```
GET /api/v1/admins        as B   ->  the row with "is_you": true   -> B's real admin/workspace id
GET /api/v1/users/info    as B   ->  B's user uuid AND login email
```

The login email matters as much as the id. A membership invite addressed to a plus-alias that is not
the account's actual login will be accepted by the invite endpoint and then **fail at accept**
(`cannot accept others' admin`), leaving the principal `PENDING`. Every subsequent "refused" result
then measures a **non-member** rather than the restricted role you meant to test — and the output is
indistinguishable from the correct run. That is the most dangerous shape of this bug: a
correct-looking negative obtained against the wrong principal.

### Three ids that are easy to conflate

Keep them separate in the brief and in the script, because they are all UUIDs and the API accepts
whichever shape it is handed:

- **user id** (the identity, from `users/info`),
- **admin/membership id** (the principal *within a workspace*; the workspace selector header wants
  this, and so do transfer/ownership fields),
- **workspace/tenant id** (which may *equal* the owner's admin id, which is exactly why this gets
  conflated).

When a field rejects one with `can't find to user`, that is the API telling you which of the three
it wanted — see the validator-as-schema-oracle loop in `idor-access-control.md`.

## Case 14 — a UNIFORM error across many DISTINCT input shapes means you never reached the validator

Symptom: you probe an endpoint with a dozen different body shapes — different field names, an empty
object, an array, a bare string, alternate content types, with and without credentials — and **every
one returns the identical response**. It is tempting to read that as "the schema is something I have
not guessed yet" and keep guessing.

It usually means the opposite: **the handler 404s (or 403s) on a LOOKUP before any serializer runs.**
There is no validation error to harvest because validation never executes. Shape probing is
information-free and every further guess costs a request for zero bits.

This is the inverse of the validation-before-authz trap (Case 13 and `idor-access-control.md`):
there, a 4xx naming a *parameter* had not yet answered the authz question. Here, a 4xx naming
*nothing* means you are upstream of the parameters entirely.

### How to tell the two apart — compare the 404 BODY, not the status

Measured on `sso.acme.example` 2026-10-30:

| path | POST result |
|---|---|
| `/api/sso/v1/jwt/token/login` | `404` **empty body** — the app own 404, view was reached |
| `/api/sso/v1/jwt/token/zzzznope` | `404` **HTML** `<title>Not Found</title>` — route missing |

An empty/JSON 404 vs the server HTML 404 page distinguishes "reached the view, lookup failed" from
"no such route". Also probe `OPTIONS`: DRF answers with the view metadata
(`{"name":"Jwt Login","parses":[...]}`) and a wrong method yields `405 METHOD_NOT_ALLOWED` with an
error envelope — both prove the view exists even while POST 404s.

### What to do instead

1. Stop enumerating shapes. Record the shapes already excluded so the next pass does not repeat them.
2. Make the lookup SUCCEED: obtain or mint the object the handler is looking for (on your own
   accounts), then probe the schema with a valid key present.
3. Or go read the real caller — a mobile app, an SPA bundle, or device firmware. A production caller
   gives you the exact contract for free, and `framework-misconfig.md` has the offline-package
   recipe for the firmware case.

## Case 15 — resolve template variables before you name a path (and before you declare a limit)

Two mistakes from the same root, both made on a real engagement in one sitting, both caught by a
follow-up lane:

**1. A grep for concrete strings silently skips the interesting paths.**
Hunting a unix socket in a 6 MB bundle, a grep for `unix:[^;" ]+` returned exactly one concrete
path — and it was the boring one (a static-asset server). The two that mattered were behind
template variables:

```js
Xr = join(E.configPath, "http")
Ay = join(Xr, "uos-http.sock")      // the header-trusting ADMIN app
Ty = join(Xr, "uos-auth.sock")      // the auth backend
w5 = join(Xr, "uos-internal.sock")  // static assets  <- the only one grep found
```

The admin socket was named in the finding as the asset socket. The finding was *stronger* than
written, but it was wrong. **When a config shows `unix:${Var}` or any interpolated path, resolve the
variable before you write the path down.** Grep for the assignment (`Var\s*=`), not just for
concrete literals, and expect the valuable endpoints to be the interpolated ones.

**2. "That is runtime state, not verifiable offline" is usually premature.**
The same engagement parked a privilege-escalation chain as a LEAD because the *directory modes* of a
`/data/...` path "only exist at runtime". But the service **creates those directories itself** — so
the modes were in the shipped artifact the whole time (an app `mkdir`/`ensureDir`, a pre-start hook,
systemd `StateDirectoryMode=`/`ConfigurationDirectoryMode=`, `UMask=`, or the package `postinst`),
alongside `/data` own mode in the image tar metadata. Resolving it promoted the LEAD to CONFIRMED
with **zero hardware**.

**Before declaring that something needs a running device, ask who creates it.** Config a program
generates about itself is in the program. The checklist for a path-permission question:

- the tar/layer metadata for every shipped parent directory (mode + uid)
- `mkdir` / `mkdirp` / `ensureDir` / `install -d` / `mkdir -p` calls near the path
- the systemd unit: `RuntimeDirectory*`, `StateDirectory*`, `ConfigurationDirectory*`, `UMask=`,
  `User=`, `Group=`
- the package `postinst` / `preinst`
- any `chmod` / `chown` that widens access after creation

Related: Case 12 (an uncalled initializer is not an enabled feature) and Case 14 (a uniform error
across distinct inputs means you never reached the validator). All three are the same discipline —
read what the code *does*, not what a string search suggests.
