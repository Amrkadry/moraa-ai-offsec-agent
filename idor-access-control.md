# Moraa — IDOR / Broken Access Control (#1 paid class)

> Folds in HackTricks `idor`, H1 (McHire 64M-applicant `/api/lead/cem-xhr` seq-ID breach; GitLab
> ML-registry incremental-model IDOR $1,160; Unikrn enumeration; "Rise of IDOR" — valid IDOR reports
> +29% YoY), and our the vendor two-account discipline (order/address/Zendesk/console — all clean because
> authz was enforced; the wins came from CORS/creds instead). Cross-ref [[framework-misconfig]] (authz
> status-code methodology), [[graphql]] (nested-resolver IDOR), [[jwt]] (claim-swap).

## The method that actually proves it: TWO ACCOUNTS
Register **A** (attacker) and **B** (victim). Capture B's full authenticated request set. Replay each
with **A's session, B's object IDs**. A guessed/random UUID proves NOTHING (`NOT_FOUND` is correct for
both "not yours" and "doesn't exist"). A finding = **A's session returns B's data/effects on a REAL B
object**, or a clean cross-account write. This is the discipline that keeps you out of false-positive hell.

**The three traps (each cost real hours on live programs):**
1. **400-before-403 (validation-before-authz):** a malformed ID returns 400 from schema validation
   *before* the authz check runs. 400≠403 is NOT a bypass. **Always retry with a well-formed, valid-shaped
   ID** before concluding anything.
2. **Fake-id vs valid-foreign:** only a genuinely valid foreign object id (or a clean 2-account test) proves it.
3. **Accept-but-ignore:** the API takes your injected `userId`/`tenantId`/`company_id` and silently
   ignores it (identity derived from session). Looks exploitable, is inert. **Proof requires the RESPONSE
   to reflect the foreign object**, not just a 200 on acceptance.

## Impact gate — whose data came back?

The falsifier that kills most would-be IDORs (the Q8 identity check from [[validate]], stated for
this class): **the foreign-identity response must contain real FOREIGN data** — another account's
PII/content in the body, produced by their id under your session.

- A `200` is not data. Nulls where the sensitive fields should be = authz working — select the
  sensitive fields explicitly and diff anonymous vs foreign vs owner before calling it.
- Your own id echoed back, a type name, an empty array, or an id you fabricated = the kill signal
  ("the victim ID in the response is your own test account's").
- The own-owner row of the safe-oracle table below is the control: if even YOUR own object errors,
  the 403/401 on foreign ids was never an authz decision.
- One identity = unproven, whatever the status code. Two accounts minimum, and the write-up shows
  A's session reading B's data with both roles named.

## Where IDs hide (check ALL — the forgotten spot is the bug)
Path `/api/user/1234` · query `?id=42` · JSON body (incl. **deeply nested** and **inside arrays**:
`{"items":[{"id":..}]}`) · GraphQL variables + **nested resolver args** · batch/bulk endpoints ·
multipart fields · headers (`X-Account-Id`, `X-Org-Id`, `X-Impersonate`, `X-User-Id`) · cookies ·
**JWT claims** (swap `sub`/tenant — see [[jwt]]) · WebSocket message fields · gRPC-web.

## ID format → enumeration strategy
| Format | Enumerable? | Play |
|---|---|---|
| Sequential int (`64185742`) | **YES — highest value** | increment/decrement loop; McHire = 64M records this way |
| MongoObjectId (`650f..`) | partial (timestamp+counter) | narrow by known time window |
| Short composite (`C-285-100`) | often yes (~26M) | brute in hours; **encoding (hex/base64) adds NO entropy** — decode, enumerate, re-encode |
| hashids / short slug | maybe | check for a leak source first |
| UUIDv1 | time-based, partially predictable | rare, but note it |
| UUIDv4 | **no** — need a LEAK | hunt leak sources ↓ |
**Where valid foreign IDs leak** (for UUIDv4): search/autocomplete endpoints, notifications, exports/CSV,
error messages, public profiles, `Referer`, shared links, invitation flows, admin/list endpoints,
**redirect Location headers** (our shop invoice redirect leaked a `customerId`), and sibling API responses.

## Enumeration one-liners
```bash
# sequential loop, keep only hits with real data
for id in $(seq 64185700 64185742); do
  curl -s -X PUT https://T/api/lead/cem-xhr -H "Cookie: auth=$A" \
    -H 'Content-Type: application/json' -d "{\"lead_id\":$id}" | jq -e '.email' >/dev/null && echo "HIT $id"; done
# ffuf, filter the 404/deny template
ffuf -u 'https://T/download?id=FUZZ' -b "SESSION=$A" -w <(seq 0 20000) -fr 'not found|forbidden'
```
Be gentle on production; a small proof sample (5–10), then STOP — never mass-harvest third-party PII;
redact it in the report.

## Beyond horizontal read — the full class
- **Method swap:** `GET`→`PUT/PATCH/DELETE/POST` on the same resource; `HEAD`/`OPTIONS`; override headers
  (`X-HTTP-Method-Override`, `_method`). Read-only authz often forgets the write verbs.
- **Version / sibling route:** `/v1` vs `/v2` vs `/internal` vs `/admin` vs legacy/mobile/partner routes —
  authz frequently not backported. High-yield, under-tested.
- **Mass assignment (H1 top pattern):** inject server-controlled fields into a create/update body —
  `role`, `isAdmin`, `plan`, `verified`, `price`, `total`, `userId`, `orgId`, `status`. Finding = the
  RESPONSE shows the field took effect. (Our shop test: schema *rejected* extra fields — that's the clean case.)
- **Vertical privesc:** **build the full privilege matrix BEFORE claiming a gap** — we once retracted a
  "BAC" finding after learning the low-priv role legitimately held those privileges. Map role→privilege first.
- **Search-index authz bypass (blind):** inject boolean constraints into a search query (`... AND item_id=23`)
  and use 200/204 / body-length / timing as an oracle to read fields you can't fetch directly. This is how
  search endpoints leak what the direct GET protects — retest search even when the object read is hardened.
- **Nested-resolver IDOR (GraphQL):** a top-level query you're allowed nests into an object you're not
  (`order{ customer{ email } }`). Nested resolvers often skip the top-level authz — see [[graphql]].

## ORM-leak methodology ("ORM Leaking More Than You Joined For" — PortSwigger Research Top 10
2025 #2, Alex Brown) — distinct from classic IDOR, exploits the query-building layer itself
Classic IDOR is "the object-ownership check is missing." This is different: the ownership check
can be perfectly correct on the *primary* resource, but a search/filter/sort parameter that gets
passed through an ORM (Django, Rails ActiveRecord, Sequelize, Hibernate/JPA, Prisma) can still
**traverse relationships the API never intended to expose**, because the ORM happily follows a
foreign-key/relation path the developer only tested with the intended top-level field. Same root
idea as GraphQL's nested-resolver IDOR (below) but applies to plain REST APIs with filter/sort/
search query params, wherever the backend maps a query param onto an ORM field lookup.
```
# baseline — filter on the resource's own field works as expected
GET /api/orders?filter[status]=shipped

# probe — does the filter param accept a RELATION path, not just a flat field?
GET /api/orders?filter[customer.email]=victim@example.com        # dot/bracket relation traversal
GET /api/orders?sort=customer.creditCard.last4                    # sort leaking via join, not just filter
GET /api/orders?filter[customer.organization.apiKey]=*            # multi-hop relation chain
GET /api/orders?search=customer__email:victim@example.com         # Django-style double-underscore lookup
```
Proof bar: the response must expose or infer data from the **related** table (a different customer/
tenant's field) that your own account's row doesn't legitimately carry — not just "the filter
param accepted unexpected syntax." A boolean-oracle variant applies when the field itself isn't
returned but its presence/absence changes the result set (does `filter[customer.isAdmin]=true`
change which rows come back, even if `isAdmin` is never displayed — same discipline as the
existing search-index-authz-bypass technique above, applied one relation hop deeper). Worth
testing on ANY endpoint that takes a `filter`/`sort`/`search`/`orderBy`/`include`/`expand` query
param backed by an ORM, especially where the API already demonstrates one relation exists (e.g.
`?include=customer` is a documented feature) — that's the strongest signal the ORM traversal path
is live and reachable from user input.

## Chain to maximum impact (write the "so what")
IDOR on email/phone change → password reset → **ATO**. IDOR on a role/permission grant → **admin**.
IDOR on export/list → **mass PII**. IDOR + leaked JWT/CSRF token → session takeover. Say who is affected
and the $/PII/DA, not just "can read object 42".

## Authz status-code cheatsheet (from [[framework-misconfig]])
401 = unauth · 403 = role/privilege · 403 = CSRF token · **400 = validation-before-authz (TRAP)** ·
404 = ownership-scoped (exists-but-not-yours, indistinguishable by design) · 200 = reached.

## The SAFE authz oracle — testing a DELETE/destructive route without destroying anything

Problem: the route you most want to test (`DELETE /comments/delete/<id>?authorId=`) is exactly the
one you must not fire blind at production. If authz is broken you just deleted a real user's data.
And you frequently do NOT have a second account (expired token, single-tenant program).

Solution: **vary only the owner id, and pin the object id to something well-formed but nonexistent.**
A broken check then reveals itself by *how far the request gets*, not by destroying data.

```bash
# DOC = a real object, CID = a well-formed but ABSENT child id (e.g. 999999)
# FOREIGN = a real foreign owner id (harvest from the public list endpoint), MINE = my own uuid
d(){ printf "%-40s " "$1"; shift; curl -s -X DELETE -w " [%{http_code}]\n" "$@"; }
d "unauth + foreign owner"         "$U/$DOC?commentId=$CID&authorId=$FOREIGN"
d "sessionA + FOREIGN + fake id"   -H "Cookie: $C" "$U/$DOC?commentId=$CID&authorId=$FOREIGN"
d "sessionA + OWN + fake id"       -H "Cookie: $C" "$U/$DOC?commentId=$CID&authorId=$MINE"
d "sessionA + owner param omitted" -H "Cookie: $C" "$U/$DOC?commentId=$CID"
d "sessionA + duplicated owner"    -H "Cookie: $C" "$U/$DOC?commentId=$CID&authorId=$MINE&authorId=$FOREIGN"
```

Reading it — **the own-owner row is the control that makes the whole table trustworthy**:

| rows | verdict |
|---|---|
| unauth `401`, foreign `403`, **own `5xx`/not-found** | ENFORCED. Authz runs *before* object resolution, so the `403` is a real authz stop, not a generic error. Clean negative you can write down. |
| foreign and own return the **same** error | INCONCLUSIVE — you may be failing on the absent object in both cases and never reaching the check. Re-test with a real object id you own. |
| foreign gets *past* the check (reaches the not-found/5xx path like the own row does) | **BROKEN** — authz is missing. You now know this *without* having deleted anything. Escalate to a proper two-account proof before reporting. |

Also fold in: duplicating the owner param tests **HPP on the authz check** (last-wins/first-wins
parsers are a classic bypass) — a `400` here is a good sign, a `200` is a finding.

### Re-run this whenever the build id changes

A rebuild/refactor is the single most likely moment for an authz check to get dropped. On a Next.js
target, diff `buildId` (`/_next/static/<buildId>/_buildManifest.js`) between passes; if it moved,
re-run the oracle above. It is ~5 requests and it is the cheapest regression test you own.

Proven on learn.acme.example 2026-09-29: webpack to Turbopack rebuild, route list byte-identical,
authz intact — confirmed in 5 requests with zero risk to production data.

---

## Free second identity: the app that auto-provisions an anonymous account

**Where it paid:** `designer.svc.acme.example` (the vendor's design product), 2026-10-01. It closed a blocker that a
previous pass had explicitly given up on ("if a genuinely fresh, real second identity is ever
obtained...").

The hard part of IDOR work is usually not the payload, it is **getting identity B**. Signup can need
email, captcha, a private key, phone, or an invite. But a large class of "try before you sign up"
products silently create a real server-side account for an anonymous visitor on first contact:

```
$ curl -s https://designer.svc.acme.example/user/me -H 'X-App-Build: <build>'
{"data":{"user":{"ssoId":"0d907c2f-ae72-4958-bc78-1bc668be6473",
 "email":"0d907c2f-...@temp-account.com","role":"nobody","isTemp":true,
 "projectCount":0,"createdAt":"..."}}}
# + Set-Cookie: <app>|sid=...   <-- a full session for a DISTINCT identity
```

That is identity B: a different `ssoId`, its own session, its own objects — obtained with one
unauthenticated GET, no email, no captcha. And it can usually **create** objects
(`POST /project` -> 200 with a new id), which gives you the much stronger test direction:
**real account A attacking an object owned by B**, rather than only B attacking A.

### Why you want both directions
Guards are often asymmetric. A "can the anonymous tier see paid data" check may exist while
"can a paid user see another tenant's data" does not — or the reverse. Run the full route matrix
A -> B's object *and* B -> A's object. In the vendor case both directions returned
`403 errors.project.access` on all 21 routes, which is what made the negative trustworthy.

### How to spot the pattern
- a product with a usable demo/guest mode ("try the designer", "start without an account");
- a `isTemp` / `isGuest` / `anonymous` / `temp-account.com` flag or synthetic email in the user object;
- an unauthenticated `GET /user/me`-style route that returns **200** rather than 401;
- a session cookie set on a request that carried no credentials.

### The limit — find it before you trust the result
Apps that do this usually also carry a **temp-account gate** on the actions that cost money or send
mail. Here: `errors.user.tempUserNotAllowed` on `POST /project/:id/duplicate`,
`POST /project/:id/share-blueprint` and `POST /project/:id/invites`. Those three can only be tested
in the real -> temp direction, so enumerate the gate and say plainly which routes it excludes rather
than reporting the whole matrix as covered.

### Ethics / safety note
Both identities are yours, so creating objects under the temp account and attacking them from your
real account is a self-owned test — no third-party data, no production state you do not own. That is
what makes this acceptable where "find a victim object" would not be.

## Case — two-layer fencing + account-state gates FIRST (a subscription-billing SaaS dashboard)

That platform's dashboard showed the **clean** shape of both fences, worth having as the reference
picture of what "no bug" looks like:

1. **Edge 403 ≠ app 404.** Unauthenticated requests to *every* API route return a uniform
   CloudFront-edge `403` (55-byte body, identical everywhere) — the auth wall is at the edge, and it
   gives you **zero route-existence information**. Only with a valid session do you reach the app,
   where foreign objects get an ownership-scoped `404 {"code":7233}` that is **byte-identical to the
   404 for a nonexistent id** (deadbeef control) — no existence oracle at either layer. When a
   target shows one uniform edge status across all paths, don't read anything into per-path 403s:
   authenticate first, then re-run the matrix.
2. **Enumerate account-STATE gates before planning mutation lanes.** The `/me` response carries
   `email_verified:false` — and a single flag turns out to gate a whole lane: invite creation dies
   with `403 {"code":7869,"You must verify your email to perform this action"}` *before* role
   validation (every garbage role value returns the same 7869, so the gate also hides the valid
   enum). Lesson: on any new SaaS dashboard, pull `/me`, diff the two accounts' flags
   (email_verified, plan, feature_flags, mfa_enabled) and resolve which mutation lanes those flags
   gate — before burning the session budget on a lane that dies on request one. Same idea as the
   temp-account gate above, but for *verified* accounts: an unverified-but-authenticated session is
   a third identity class, and it is usually the one you are holding.
3. **Strict-schema tell.** A mutation that rejects mass-assignment with
   `email_verified: Extra inputs are not permitted` is Pydantic/FastAPI-family strict parsing —
   don't waste probes on classic mass-assignment shapes on that endpoint; look instead for
   *type-confusion* or *param-alias* variants (snake_case vs camelCase are converted by an
   explicit `dangerouslySnakeCaseRequest` layer, so dual-casing retries are cheap and sometimes
   bypass a validator that only knows one casing).

Harness: `scripts/rc_authz_sweep.py` (routes × {unauth,A,B} matrix, flags 200s, saves JSON).

---

## The validation wall: finish the body BEFORE you read the authz verdict

The 400-vs-403 trap in this doc has a sharper operational form. On a strongly-typed backend
(Go + `binding`/`validator`, Java + Bean Validation, .NET model binding) a write route refuses in
**layers**, and only the last layer is the authorization answer:

```
1. body deserialization   -> 400 "cannot unmarshal string into Go value of type struct {...}"
2. required-field check   -> 400 "Key: 'XReq.ToOwner' Error:Field validation for 'ToOwner' failed"
3. field-type/format      -> 400 "invalid UUID length: 23"   /  "ParseAddr(...): invalid data"
4. referent lookup        -> 400 "can't find to user"  /  404 "not exist: device <id>"
5. OWNERSHIP / AUTHZ      -> 400 "device <id> does not belong to user <caller>"  / 403 / 200
```

**A refusal from layers 1-4 is not a security result.** It means your request never reached the
check you care about. In one session this cost three separate wrong verdicts:

- `PUT /admins/{id}/activations` -> `400 cannot unmarshal string ...` read as "revoke is refused,
  the finding stands". It was a **double-encoded body** (the helper already JSON-encoded it). With a
  dict: **200**. The finding was false and died.
- `PATCH /workspaces` with the field under test but no required `name` -> `400 invalid name format`
  read as "the field is not writable". With `name` supplied: **200** (and the field silently
  ignored — the real answer, see the silent-200 rule below).
- `POST /devices/ownership-transfer` -> nine body shapes, all the same `400`, read as "route
  refuses". All nine omitted the required `to_owner`. Supplying it produced the genuine authz
  refusal: `device <id> does not belong to user <caller>`.

### Turn the validator into a free schema oracle

Those errors **name the field for you**. Go's `validator` prints `Key: '<Struct>.<Field>'`, which
gives you the struct name, the exact field, and the failing rule; the next layer then tells you the
type (`invalid UUID length`, `ParseAddr`, `ParsePrefix`); the layer after names the referent lookup.
So the loop is:

1. POST `{}` and read the first missing-field name.
2. Add it with an obviously-wrong-typed value; the type error tells you the real type.
3. Repeat until the error stops being about *shape* and starts being about *identity or ownership*.
4. **Only then** record the authz verdict.

This is strictly better than guessing body shapes, needs no bundle, and works through a WAF. Do it
in the **attack direction** (the unauthorized principal) — an unauthorized caller is refused
regardless of body shape, so walking the validator leaks no risk and changes no state.

### Watch for two different refusal layers wearing the same code

On one host both of these appeared on the same route family:

- `403 no permission` — plain text, the **workspace/tenant membership** check;
- `403 {"err":{"msg":"Forbidden"}}` — JSON, the **resource/entitlement** check (device state,
  subscription tier).

They mean different things: the first says "not your tenant", the second says "your tenant, but this
object or plan does not permit it". A `Forbidden` that the *owner* also receives is an entitlement
gate, not an authz finding — chase the entitlement, not the role.

### And a 400 can BE the authz answer

Do not invert this rule into "400 always means validation". The same estate returned
`400 {"error":"Permission Denied"}` for a member attempting self-escalation, and
`400 "device … does not belong to user …"` for a cross-account transfer. Both are authorization
refusals wearing a 400. **The read-back, not the status code, settles every write.**
